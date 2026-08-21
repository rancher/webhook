// Package limitrange holds the Admitters and Validator for webhook
// validation of requests modifying LimitRange objects. It rejects all attempts
// by users to create, modify, or delete the rancher-managed resource.
package limitrange

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

// defaultLimitRangeLabel is the label that Rancher sets on the namespace
// LimitRange it manages. LimitRanges carrying this label cannot be created,
// modified, or deleted by regular users. This includes indirect creation by
// adding the marker label to an unmanaged user resource. Note, yes, the
// limitrange resource use the same label as resource quota resources.
const defaultLimitRangeLabel = "resourcequota.management.cattle.io/default-resource-quota"

// limitrangeGVR is the GroupVersionResource for core LimitRange objects.
var limitrangeGVR = schema.GroupVersionResource{
	Group:    "",
	Version:  "v1",
	Resource: "limitranges",
}

// Validator implements admission.ValidatingAdmissionWebhook.
type Validator struct {
	admitter admitter
}

// NewValidator returns a LimitRange validator.
func NewValidator() *Validator {
	return &Validator{
		admitter: admitter{},
	}
}

// GVR returns the GroupVersionResource that this webhook handles.
func (v *Validator) GVR() schema.GroupVersionResource {
	return limitrangeGVR
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
	listTrace := trace.New("limitrange Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldRq, newRq, err := objectsv1.LimitRangeOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to decode LimitRange from request: %w", err)
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

// hasMarkerLabel reports whether rq is a Rancher-managed namespace LimitRange resource.
func hasMarkerLabel(rq *corev1.LimitRange) bool {
	return rq.Labels[defaultLimitRangeLabel] == "true"
}
