package globalrolebinding

import (
	"fmt"
	"net/http"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	rbacvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "globalrolebindings",
}

// NewValidator returns a new validator for GlobalRoleBindings.
func NewValidator(grCache v3.GlobalRoleCache, resolver rbacvalidation.AuthorizationRuleResolver) *Validator {
	return &Validator{
		resolver:    resolver,
		globalRoles: grCache,
	}
}

// Validator is used to validate operations to GlobalRoleBindings.
type Validator struct {
	resolver    rbacvalidation.AuthorizationRuleResolver
	globalRoles v3.GlobalRoleCache
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update, admissionregistrationv1.Delete}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) *admissionregistrationv1.ValidatingWebhook {
	return admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope)
}

// Admit handles the webhook admission request sent to this webhook.
func (v *Validator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("globalRoleBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	newGRB, err := objectsv3.GlobalRoleBindingFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}

	// Pull the global role to get the rules
	globalRole, err := v.globalRoles.Get(newGRB.GlobalRoleName)
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}
		switch request.Operation {
		case admissionv1.Delete: // allow delete operations if the GR is not found
			return &admissionv1.AdmissionResponse{
				Allowed: true,
			}, nil
		case admissionv1.Update: // only allow updates to the finalizers if the GR is not found
			if newGRB.DeletionTimestamp != nil {
				return &admissionv1.AdmissionResponse{
					Allowed: true,
				}, nil
			}
		}
		// other operations not allowed
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Status:  "Failure",
				Message: fmt.Sprintf("referenced globalRole %s not found, only deletions allowed", newGRB.Name),
				Reason:  metav1.StatusReasonUnauthorized,
				Code:    http.StatusUnauthorized,
			},
			Allowed: false,
		}, nil
	}

	response := &admissionv1.AdmissionResponse{}
	auth.SetEscalationResponse(response, auth.ConfirmNoEscalation(request, globalRole.Rules, "", v.resolver))

	return response, nil
}
