package common

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	controllerv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	admissionv1 "k8s.io/api/admission/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/apis/rbac"
	rbacValidation "k8s.io/kubernetes/pkg/apis/rbac/validation"
)

func CheckCreatorID(request *admission.Request, oldObj, newObj metav1.Object) *metav1.Status {
	status := &metav1.Status{
		Status: "Failure",
		Reason: metav1.StatusReasonInvalid,
		Code:   http.StatusUnprocessableEntity,
	}

	newAnnotations := newObj.GetAnnotations()
	if request.Operation == admissionv1.Create {
		// When creating the newObj the annotation must match the user creating it
		if newAnnotations[auth.CreatorIDAnn] != request.UserInfo.Username {
			status.Message = "creatorID annotation does not match user"
			return status
		}
		return nil
	}

	// Check that the anno doesn't exist on the update object, the only allowed
	// update to this field is deleting it.
	if _, ok := newAnnotations[auth.CreatorIDAnn]; !ok {
		return nil
	}

	// Compare old vs new because they need to be the same, no updates are allowed for
	// the CreatorIDAnn
	if oldObj.GetAnnotations()[auth.CreatorIDAnn] != newAnnotations[auth.CreatorIDAnn] {
		status.Message = "creatorID annotation cannot be changed"
		return status
	}

	return nil
}

// ValidateRules calls on standard kubernetes RBAC functionality for the validation of policy rules
// to validate Rancher rules. This is currently used in the validation of globalroles and roletemplates.
func ValidateRules(rules []rbacv1.PolicyRule, isNamespaced bool, fldPath *field.Path) error {
	var returnErr error
	for index, r := range rules {
		fieldErrs := rbacValidation.ValidatePolicyRule(rbac.PolicyRule(r), isNamespaced,
			fldPath.Index(index))
		returnErr = errors.Join(returnErr, fieldErrs.ToAggregate())
	}
	return returnErr
}

var annotationsFieldPath = field.NewPath("metadata").Child("annotations")

// CheckCreatorPrincipalName checks that if creator-principal-name annotation is set then creatorId annotation must be set as well.
// The value of creator-principal-name annotation should match the creator's user principal id.
func CheckCreatorPrincipalName(userCache controllerv3.UserCache, obj metav1.Object) (*field.Error, error) {
	annotations := obj.GetAnnotations()
	principalName := annotations[auth.CreatorPrincipalNameAnn]
	if principalName == "" { // Nothing to check.
		return nil, nil
	}

	creatorID := annotations[auth.CreatorIDAnn]
	if creatorID == "" {
		return field.Invalid(annotationsFieldPath, auth.CreatorPrincipalNameAnn, fmt.Sprintf("annotation %s is required", auth.CreatorIDAnn)), nil
	}

	user, err := userCache.Get(creatorID)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return field.Invalid(annotationsFieldPath, auth.CreatorPrincipalNameAnn, fmt.Sprintf("creator user %s doesn't exist", creatorID)), nil
		}
		return nil, fmt.Errorf("error getting creator user %s: %w", creatorID, err)
	}

	for _, principal := range user.PrincipalIDs {
		if principal == principalName {
			return nil, nil
		}
	}

	return field.Invalid(annotationsFieldPath, auth.CreatorPrincipalNameAnn, fmt.Sprintf("creator user %s doesn't have principal %s", creatorID, principalName)), nil
}

// CheckCreatorAnnotationsOnUpdate checks that the creatorId and creator-principal-name annotations are immutable.
// The only allowed update is removing the annotations.
// This function should only be called for the update operation.
func CheckCreatorAnnotationsOnUpdate(oldObj, newObj metav1.Object) *field.Error {
	oldAnnotations := oldObj.GetAnnotations()
	newAnnotations := newObj.GetAnnotations()

	for _, annotation := range []string{auth.CreatorIDAnn, auth.CreatorPrincipalNameAnn} {
		if _, ok := newAnnotations[annotation]; ok {
			// If the annotation exists on the new object it must be the same as on the old object.
			if oldAnnotations[annotation] != newAnnotations[annotation] {
				return field.Invalid(annotationsFieldPath, annotation, "annotation is immutable")
			}
		}
	}

	return nil
}
