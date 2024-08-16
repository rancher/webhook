package token

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/rancher/webhook/pkg/admission"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "tokens",
}

// Validator validates tokens.
type Validator struct {
	admitter admitter
}

// NewValidator returns a new Validator instance.
func NewValidator() *Validator {
	return &Validator{
		admitter: admitter{},
	}
}

// GVR returns the GroupVersionResource.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by the validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Update, admissionregistrationv1.Create}
}

// ValidatingWebhook returns the ValidatingWebhook.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{
		*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope, v.Operations()),
	}
}

// Admitters returns the admitter objects.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct{}

// Admit handles the webhook admission requests.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("tokenValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	if request.Operation == admissionv1.Create || request.Operation == admissionv1.Update {
		err := a.validateTokenFields(request)
		if err != nil {
			return admission.ResponseBadRequest(err.Error()), nil
		}
	}

	return admission.ResponseAllowed(), nil
}

// PartialToken represents raw values of Token fields.
type PartialToken struct {
	LastUsedAt *string `json:"lastUsedAt"`
}

func (a *admitter) validateTokenFields(request *admission.Request) error {
	var tok PartialToken

	err := json.Unmarshal(request.Object.Raw, &tok)
	if err != nil {
		return fmt.Errorf("failed to get PartialToken from request: %w", err)
	}

	if tok.LastUsedAt != nil {
		if _, err = time.Parse(time.RFC3339, *tok.LastUsedAt); err != nil {
			return field.TypeInvalid(field.NewPath("lastUsedAt"), tok.LastUsedAt, err.Error())
		}
	}

	return nil
}
