package common

import (
	"fmt"
	"net/http"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	admissionv1 "k8s.io/api/admission/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
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

// CheckForVerbs checks that all the rules in the given list have a verb set
func CheckForVerbs(rules []rbacv1.PolicyRule, fldPath *field.Path) error {
	for i := range rules {
		rule := rules[i]
		if len(rule.Verbs) == 0 {
			return fmt.Errorf("policyRules must have at least one verb: %s", rule.String())
		}
	}
	return nil
}
