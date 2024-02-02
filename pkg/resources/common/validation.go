package common

import (
	"errors"
	"net/http"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	admissionv1 "k8s.io/api/admission/v1"
	rbacv1 "k8s.io/api/rbac/v1"
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
