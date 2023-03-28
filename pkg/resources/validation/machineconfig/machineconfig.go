package machineconfig

import (
	"github.com/rancher/webhook/pkg/admission"
	v1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	"github.com/rancher/webhook/pkg/resources/validation"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "rke-machine-config.cattle.io",
	Version:  "v1",
	Resource: "*",
}

// Validator for validating machineconfigs.
type Validator struct {
	admitter admitter
}

// NewValidator returns a new machineconfig validator.
func NewValidator() *Validator {
	return &Validator{
		admitter: admitter{},
	}
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Update}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope, v.Operations())}
}

// Admitters returns the admitter objects used to validate machineconfigs.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct{}

// Admit handles the webhook admission request sent to this webhook.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("machineConfigValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldUnstrConfig, unstrConfig, err := v1.UnstructuredOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}

	response := &admissionv1.AdmissionResponse{}
	if response.Result = validation.CheckCreatorID(request, oldUnstrConfig, unstrConfig); response.Result != nil {
		return response, nil
	}

	response.Allowed = true
	return response, nil
}
