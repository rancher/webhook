package machineconfig

import (
	"fmt"

	"github.com/rancher/webhook/pkg/admission"
	v1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	"github.com/rancher/webhook/pkg/patch"
	"github.com/rancher/webhook/pkg/resources/common"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

// Mutator implements admission.MutatingAdmissionWebhook.
type Mutator struct{}

// GVR returns the GroupVersionKind for this CRD.
func (m *Mutator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this mutator.
func (m *Mutator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create}
}

// MutatingWebhook returns the MutatingWebhook used for this CRD.
func (m *Mutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.MutatingWebhook {
	mutatingWebhook := admission.NewDefaultMutatingWebhook(m, clientConfig, admissionregistrationv1.NamespacedScope, m.Operations())
	mutatingWebhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNoneOnDryRun)
	return []admissionregistrationv1.MutatingWebhook{*mutatingWebhook}
}

// Admit is the entrypoint for the mutator. Admit will return an error if it unable to process the request.
func (m *Mutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if request.DryRun != nil && *request.DryRun {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}

	listTrace := trace.New("machine config Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	config, err := v1.UnstructuredFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get object from request: %w", err)
	}

	common.SetCreatorIDAnnotation(request, config)

	response := &admissionv1.AdmissionResponse{}
	if err := patch.CreatePatch(request.Object.Raw, config, response); err != nil {
		return nil, fmt.Errorf("failed to create patch: %w", err)
	}
	response.Allowed = true
	return response, nil
}
