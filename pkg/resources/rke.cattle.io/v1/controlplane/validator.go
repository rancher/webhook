package controlplane

import (
	"fmt"

	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	v1 "github.com/rancher/webhook/pkg/generated/objects/rke.cattle.io/v1"
	"github.com/rancher/webhook/pkg/resources/common"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var gvr = schema.GroupVersionResource{
	Group:    rkev1.SchemeGroupVersion.Group,
	Version:  rkev1.SchemeGroupVersion.Version,
	Resource: "rkecontrolplanes",
}

var _ admission.ValidatingAdmissionHandler = &Validator{}

// NewValidator returns a new Validator for RKEControlPlane resources.
func NewValidator() *Validator {
	return &Validator{}
}

// Validator conforms to the admission.ValidatingAdmissionHandler interface.
type Validator struct {
	admitter admitter
}

// GVR returns the GroupVersionResource for RKEControlPlane.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns the list of admission operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
		admissionregistrationv1.Update,
	}
}

// ValidatingWebhook returns the ValidatingWebhook used for RKEControlPlane.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope, v.Operations())}
}

// Admitters returns the admitter objects used to validate RKEControlPlanes.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct{}

// Admit handles the webhook admission request for RKEControlPlane.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if request.Operation != admissionv1.Create && request.Operation != admissionv1.Update {
		return admission.ResponseAllowed(), nil
	}

	newControlPlane, err := v1.RKEControlPlaneFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get RKEControlPlane from request: %w", err)
	}

	if response := validateDataDirectories(newControlPlane); !response.Allowed {
		return response, nil
	}

	return admission.ResponseAllowed(), nil
}

func validateDataDirectories(cp *rkev1.RKEControlPlane) *admissionv1.AdmissionResponse {
	dataDirectories := map[string]string{
		"Distro":       cp.Spec.DataDirectories.K8sDistro,
		"Provisioning": cp.Spec.DataDirectories.Provisioning,
		"System Agent": cp.Spec.DataDirectories.SystemAgent,
	}

	for name, dir := range dataDirectories {
		if response := common.ValidateDataDirectoryFormat(dir, name); !response.Allowed {
			return response
		}
	}

	return common.ValidateDataDirectoryHierarchy(dataDirectories)
}
