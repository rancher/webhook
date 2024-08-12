// Package clusterrepo is used for validating clusterrepo admission request.
package clusterrepo

import (
	"errors"
	"fmt"

	catalogv1 "github.com/rancher/rancher/pkg/apis/catalog.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	v1 "github.com/rancher/webhook/pkg/generated/objects/catalog.cattle.io/v1"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

var gvr = schema.GroupVersionResource{
	Group:    "catalog.cattle.io",
	Version:  "v1",
	Resource: "clusterrepos",
}

// NewValidator will create a newly allocated Validator.
func NewValidator() *Validator {
	return &Validator{}
}

// Validator conforms to the webhook.Handler interface and is used for validating request for clusterrepos.
type Validator struct {
	admitter admitter
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{
		admissionregistrationv1.Update,
		admissionregistrationv1.Create,
	}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope, v.Operations())}
}

// Admitters returns the admitter objects used to validate clusterrepos.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
}

// Admit is the entrypoint for the validator. Admit will return an error if it is unable to process the request.
// If this function is called without NewValidator(..) calls will panic.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	fieldPath := field.NewPath("clusterrepo")

	if request.Operation == admissionv1.Create || request.Operation == admissionv1.Update {
		newClusterRepo, err := v1.ClusterRepoFromRequest(&request.AdmissionRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to get clusterRepo from request: %w", err)
		}

		var fieldErr *field.Error
		if err := a.validateFields(newClusterRepo, fieldPath); err != nil {
			if errors.As(err, &fieldErr) {
				return admission.ResponseBadRequest(fieldErr.Error()), nil
			}
			return nil, fmt.Errorf("failed to validate fields on ClusterRepo: %w", err)
		}
	}

	return admission.ResponseAllowed(), nil
}

func (a *admitter) validateFields(newClusterrepo *catalogv1.ClusterRepo, fieldPath *field.Path) error {
	// Both GitRepo and URL can't be specified simultaneously.
	if newClusterrepo.Spec.URL != "" && newClusterrepo.Spec.GitRepo != "" {
		return field.Forbidden(fieldPath, "both fields spec.URL and spec.GitRepo cannot be specified simultaneously")
	}

	// Either GitRepo or URL must be specified.
	if newClusterrepo.Spec.URL == "" && newClusterrepo.Spec.GitRepo == "" {
		return field.Forbidden(fieldPath, "either of fields spec.URL or spec.GitRepo must be specified")
	}

	return nil
}
