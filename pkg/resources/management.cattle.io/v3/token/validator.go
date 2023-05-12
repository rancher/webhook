package token

import (
	"fmt"
	"net/http"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/trace"
)

var tokenGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "token",
}

func NewValidator() *Validator {
	return &Validator{}
}

type Validator struct {
}

func (v *Validator) GVR() schema.GroupVersionResource {
	return tokenGVR
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Update, admissionregistrationv1.Create}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope, v.Operations())}
}

func (v *Validator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("token Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	// The only validation that needs to be done is on Update actions
	if request.Operation != admissionv1.Update {
		return &admissionv1.AdmissionResponse{Allowed: true}, nil
	}

	fieldPath := field.NewPath("token")
	var fieldErr *field.Error

	oldToken, newToken, err := objectsv3.TokenOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get old and new CRTB from request: %w", err)
	}

	if fieldErr = validateUpdateFields(oldToken, newToken, fieldPath); fieldErr != nil {
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Status:  "Failure",
				Message: fieldErr.Error(),
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			},
			Allowed: false,
		}, nil
	}
	return &admissionv1.AdmissionResponse{Allowed: true}, nil
}

// validateUpdateFields checks if the fields being changed are valid update fields
func validateUpdateFields(oldToken, newToken *apisv3.Token, fieldPath *field.Path) *field.Error {
	const reason = "field is immutable"
	switch {
	case oldToken.Token != newToken.Token:
		return field.Invalid(fieldPath.Child("token"), newToken.Token, reason)
	case oldToken.ClusterName != newToken.ClusterName:
		return field.Invalid(fieldPath.Child("clusterName"), newToken.ClusterName, reason)
	default:
		return nil
	}
}
