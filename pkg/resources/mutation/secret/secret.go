package secret

import (
	"fmt"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	"github.com/rancher/webhook/pkg/patch"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "",
	Version:  "v1",
	Resource: "secrets",
}

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
func (m *Mutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) *admissionregistrationv1.MutatingWebhook {
	mutatingWebhook := admission.NewDefaultMutatingWebhook(m, clientConfig, admissionregistrationv1.NamespacedScope)
	mutatingWebhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNoneOnDryRun)
	return mutatingWebhook
}

// Admit is the entrypoint for the mutator. Admit will return an error if it unable to process the request.
func (m *Mutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if request.DryRun != nil && *request.DryRun {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}

	listTrace := trace.New("secret Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	secret, err := objectsv1.SecretFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}

	if secret.Type != "provisioning.cattle.io/cloud-credential" {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}

	logrus.Debugf("[secret-mutation] adding creatorID %v to secret: %v", request.UserInfo.Username, secret.Name)
	newSecret := secret.DeepCopy()

	if newSecret.Annotations == nil {
		newSecret.Annotations = make(map[string]string)
	}

	newSecret.Annotations[auth.CreatorIDAnn] = request.UserInfo.Username
	response := &admissionv1.AdmissionResponse{}
	if err := patch.CreatePatch(request.Object.Raw, newSecret, response); err != nil {
		return nil, fmt.Errorf("failed to create patch: %w", err)
	}
	response.Allowed = true
	return response, nil
}
