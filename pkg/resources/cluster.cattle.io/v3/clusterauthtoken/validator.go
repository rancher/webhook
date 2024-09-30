package clusterauthtoken

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
	Group:    "cluster.cattle.io",
	Version:  "v3",
	Resource: "clusterauthtokens",
}

// Validator validates clusterauthtokens.
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
	listTrace := trace.New("clusterAuthTokenValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	if request.Operation == admissionv1.Create || request.Operation == admissionv1.Update {
		err := a.validateTokenFields(request)
		if err != nil {
			return admission.ResponseBadRequest(err.Error()), nil
		}
	}

	return admission.ResponseAllowed(), nil
}

// PartialClusterAuthToken represents raw values of ClusterAuthToken fields.
type PartialClusterAuthToken struct {
	LastUsedAt *string `json:"lastUsedAt"`
}

func (a *admitter) validateTokenFields(request *admission.Request) error {
	var partial PartialClusterAuthToken

	err := json.Unmarshal(request.Object.Raw, &partial)
	if err != nil {
		return fmt.Errorf("failed to get PartialClusterAuthToken from request: %w", err)
	}

	if partial.LastUsedAt != nil {
		if _, err = time.Parse(time.RFC3339, *partial.LastUsedAt); err != nil {
			return field.TypeInvalid(field.NewPath("lastUsedAt"), partial.LastUsedAt, err.Error())
		}
	}

	return nil
}
