// Package namespace holds the Admit handler for webhook validation of requests modifying namespace objects
package namespace

import (
	"fmt"
	"net/http"

	"github.com/rancher/webhook/pkg/admission"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	"github.com/rancher/webhook/pkg/resources/validation"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/trace"
)

// Validator validates the namespace admission request.
type Validator struct {
	sar authorizationv1.SubjectAccessReviewInterface
}

// NewValidator returns a new validator used for validation of namespace requests.
func NewValidator(sar authorizationv1.SubjectAccessReviewInterface) *Validator {
	return &Validator{
		sar: sar,
	}
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Version:  "v1",
		Resource: "namespaces",
	}
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{
		admissionregistrationv1.Update,
		admissionregistrationv1.Create,
	}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) *admissionregistrationv1.ValidatingWebhook {
	// Note that namespaces are actually CLUSTER scoped
	return admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope)
}

// Admit is the entrypoint for the validator.
// Admit will return an error if it is unable to process the request.
func (v *Validator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("Namespace Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	response := &admissionv1.AdmissionResponse{}

	// Is the request attempting to modify the special PSA labels (enforce, warn, audit)?
	// If it isn't, we're done.
	// If it is, we then need to check to see if they should be allowed.
	switch request.Operation {
	case admissionv1.Create:
		ns, err := objectsv1.NamespaceFromRequest(&request.AdmissionRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to decode namespace from request: %w", err)
		}
		if !validation.IsCreatingPSAConfig(ns.Labels) {
			response.Allowed = true
			return response, nil
		}
	case admissionv1.Update:
		oldns, ns, err := objectsv1.NamespaceOldAndNewFromRequest(&request.AdmissionRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to decode namespace from request: %w", err)
		}
		if !validation.IsUpdatingPSAConfig(oldns.Labels, ns.Labels) {
			response.Allowed = true
			return response, nil
		}
	}

	extras := map[string]v1.ExtraValue{}
	for k, v := range request.UserInfo.Extra {
		extras[k] = v1.ExtraValue(v)
	}

	resp, err := v.sar.Create(request.Context, &v1.SubjectAccessReview{
		Spec: v1.SubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Verb:     "updatepsa",
				Group:    "management.cattle.io",
				Version:  "v3",
				Resource: "projects",
			},
			User:   request.UserInfo.Username,
			Groups: request.UserInfo.Groups,
			UID:    request.UserInfo.UID,
			Extra:  extras,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("SAR request creation failed: %w", err)
	}

	if resp.Status.Allowed {
		response.Allowed = true
	} else {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: resp.Status.Reason,
			Reason:  metav1.StatusReasonUnauthorized,
			Code:    http.StatusForbidden,
		}
	}
	return response, nil
}
