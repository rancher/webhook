package globalrole

import (
	"net/http"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "globalroles",
}

// NewValidator returns a new validator used for validation globalRoles.
func NewValidator(resolver validation.AuthorizationRuleResolver) *Validator {
	return &Validator{
		resolver: resolver,
	}
}

// Validator implements admission.ValidatingAdmissionHandler
type Validator struct {
	resolver validation.AuthorizationRuleResolver
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Update, admissionregistrationv1.Create}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope, v.Operations())}
}

// Admit is the entrypoint for the validator. Admit will return an error if it unable to process the request.
// If this function is called without NewValidator(..) calls will panic.
func (v *Validator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("globalRoleValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	newGR, err := objectsv3.GlobalRoleFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}

	// object is in the process of being deleted, so admit it
	// this admits update operations that happen to remove finalizers
	if newGR.DeletionTimestamp != nil {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}

	// ensure all PolicyRules have at least one verb, otherwise RBAC controllers may encounter issues when creating Roles and ClusterRoles
	for _, rule := range newGR.Rules {
		if len(rule.Verbs) == 0 {
			return &admissionv1.AdmissionResponse{
				Result: &metav1.Status{
					Status:  "Failure",
					Message: "GlobalRole.Rules: PolicyRules must have at least one verb",
					Reason:  metav1.StatusReasonBadRequest,
					Code:    http.StatusBadRequest,
				},
				Allowed: false,
			}, nil
		}
	}

	response := &admissionv1.AdmissionResponse{}
	auth.SetEscalationResponse(response, auth.ConfirmNoEscalation(request, newGR.Rules, "", v.resolver))

	return response, nil
}
