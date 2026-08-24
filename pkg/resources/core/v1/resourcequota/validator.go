// Package resourcequota holds the Admitters and Validator for webhook
// validation of requests modifying ResourceQuota objects. It rejects all
// attempts by users to create, modify, or delete the rancher-managed resource.
package resourcequota

import (
	"fmt"

	"github.com/rancher/webhook/pkg/admission"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

// kubernetesNamespaceController is the system user who is allowed to all
// resource quotas, even the rancher-managed one. because it does so only as
// part of deleting the entire namespace.
const kubernetesNamespaceController = "system:serviceaccount:kube-system:namespace-controller"

// defaultResourceQuotaLabel is the label that Rancher sets on the namespace
// ResourceQuota it manages.  ResourceQuotas carrying this label cannot be
// created, modified, or deleted by regular users. This includes indirect
// creation by adding the marker label to an unmanaged user resource.
const defaultResourceQuotaLabel = "resourcequota.management.cattle.io/default-resource-quota"

// resourceQuotaGVR is the GroupVersionResource for core ResourceQuota objects.
var resourceQuotaGVR = schema.GroupVersionResource{
	Group:    "",
	Version:  "v1",
	Resource: "resourcequotas",
}

// Validator implements admission.ValidatingAdmissionWebhook.
type Validator struct {
	admitter admitter
}

// NewValidator returns a ResourceQuota validator.
func NewValidator() *Validator {
	return &Validator{
		admitter: admitter{},
	}
}

// GVR returns the GroupVersionResource that this webhook handles.
func (v *Validator) GVR() schema.GroupVersionResource {
	return resourceQuotaGVR
}

// Operations returns the list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
		admissionregistrationv1.Update,
		admissionregistrationv1.Delete,
	}
}

// ValidatingWebhook returns the ValidatingWebhook configuration for this validator.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	wh := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope, v.Operations())
	wh.Rules[0].Rule.Resources = []string{resourceQuotaGVR.Resource, resourceQuotaGVR.Resource + "/status"}
	return []admissionregistrationv1.ValidatingWebhook{*wh}
}

// Admitters returns the list of admitters used by this validator.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
}

// Admit validates the admission request. Note that this validator receives only
// user-made requests. Rancher requests are marked with the webhook bypass and do
// not reach this function
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("resourcequota Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldRq, newRq, err := objectsv1.ResourceQuotaOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ResourceQuota from request: %w", err)
	}
	switch request.Operation {
	case admissionv1.Create:
		if hasMarkerLabel(newRq) {
			// Reject the user's attempt to create a rancher-managed
			// quota resource.
			return admission.ResponseBadRequest(
				"users are forbidden from creating resources managed by Rancher. Remove the marker label",
			), nil
		}
	case admissionv1.Update:
		if request.SubResource == "status" {
			oldHasMarkerLabel := hasMarkerLabel(oldRq)
			newHasMarkerLabel := hasMarkerLabel(newRq)
			if oldHasMarkerLabel && !newHasMarkerLabel {
				// Reject the user's attempt to demote a Rancher-managed resource.
				return admission.ResponseBadRequest(
					"users are forbidden from changing resources managed by Rancher",
				), nil
			}
			if !oldHasMarkerLabel && newHasMarkerLabel {
				// Reject the user's attempt to promote an unmanaged resource to Rancher managed.
				return admission.ResponseBadRequest(
					"users are forbidden from promoting resources to Rancher management. Remove the marker label",
				), nil
			}
			return admission.ResponseAllowed(), nil
		}
		if hasMarkerLabel(oldRq) {
			// Reject the user's attempt to update the
			// rancher-managed quota resource
			return admission.ResponseBadRequest(
				"users are forbidden from changing resources managed by Rancher",
			), nil
		}
		if hasMarkerLabel(newRq) {
			// Reject the user's attempt to promote an unmanaged resource to Rancher managed
			return admission.ResponseBadRequest(
				"users are forbidden from promoting resources to Rancher management. Remove the marker label",
			), nil
		}
	case admissionv1.Delete:
		if request.UserInfo.Username == kubernetesNamespaceController {
			// The kubernetes controller is allowed to delete the rancher-managed resource.
			// This happens as part of deleting the containing namespace.
			return admission.ResponseAllowed(), nil
		}
		if hasMarkerLabel(oldRq) {
			// Reject the user's attempt to delete the
			// rancher-managed quota resource
			return admission.ResponseBadRequest(
				"users are forbidden from deleting resources managed by Rancher",
			), nil
		}
	default:
		return nil, admission.ErrUnsupportedOperation
	}

	return admission.ResponseAllowed(), nil
}

// hasMarkerLabel reports whether rq is a Rancher-managed namespace ResourceQuota resource.
func hasMarkerLabel(rq *corev1.ResourceQuota) bool {
	return rq.Labels[defaultResourceQuotaLabel] == "true"
}
