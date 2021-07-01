package globalrolebinding

import (
	"net/http"
	"reflect"
	"time"

	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/trace"
)

func NewValidator(grClient v3.GlobalRoleCache, grbClient v3.GlobalRoleBindingCache, escalationChecker *auth.EscalationChecker) webhook.Handler {
	return &globalRoleBindingValidator{
		escalationChecker:  escalationChecker,
		globalRoles:        grClient,
		globalRoleBindings: grbClient,
	}
}

type globalRoleBindingValidator struct {
	escalationChecker  *auth.EscalationChecker
	globalRoles        v3.GlobalRoleCache
	globalRoleBindings v3.GlobalRoleBindingCache
}

func (grbv *globalRoleBindingValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("globalRoleBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	newGRB, err := grbObject(request)
	if err != nil {
		return err
	}

	// Pull the global role to get the rules
	globalRole, err := grbv.globalRoles.Get(newGRB.GlobalRoleName)
	if err != nil {
		if errors.IsNotFound(err) {
			switch request.Operation {
			// allow delete operations if the GR associated to the GRB is not found
			case admissionv1.Delete:
				response.Allowed = true
				return nil
			// only allow updates to the finalizers if the GR associated to the GRB is not found
			case admissionv1.Update:
				existing, err := grbv.globalRoleBindings.Get(newGRB.Name)
				if err != nil {
					return err
				}
				if isFinalizerUpdate := isUpdateToFinalizersOnly(existing, newGRB); isFinalizerUpdate {
					response.Allowed = true
					return nil
				}
				response.Result = &metav1.Status{
					Status:  "Failure",
					Message: "No GlobalRole found, only updates to finalizers are allowed",
					Reason:  metav1.StatusReasonUnauthorized,
					Code:    http.StatusUnauthorized,
				}
				return nil
			}
		}
		return err
	}

	return grbv.escalationChecker.ConfirmNoEscalation(response, request, globalRole.Rules, "")
}

func grbObject(request *webhook.Request) (*rancherv3.GlobalRoleBinding, error) {
	var grb runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		grb, err = request.DecodeOldObject()
	} else {
		grb, err = request.DecodeObject()
	}
	return grb.(*rancherv3.GlobalRoleBinding), err
}

func isUpdateToFinalizersOnly(existing *rancherv3.GlobalRoleBinding, new *rancherv3.GlobalRoleBinding) bool {
	if reflect.DeepEqual(existing, new) {
		return false
	}

	if reflect.DeepEqual(existing.Finalizers, new.Finalizers) {
		return false
	}

	// if the newCopy with the existing finalizers deeply equals the existing, then only the finalizers are changing
	// managed fields are ignored
	existingCopy := existing.DeepCopy()
	existingCopy.ManagedFields = nil
	newCopy := new.DeepCopy()
	newCopy.Finalizers = existingCopy.Finalizers
	newCopy.ManagedFields = nil
	return reflect.DeepEqual(existingCopy, newCopy)
}
