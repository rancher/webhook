package cluster

import (
	"net/http"

	"github.com/rancher/webhook/pkg/admission"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

var managementGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "clusters",
}

// NewValidator returns a new validator for management clusters.
func NewValidator(sar authorizationv1.SubjectAccessReviewInterface) *Validator {
	return &Validator{
		sar: sar,
	}
}

// Validator ValidatingWebhook for management clusters.
type Validator struct {
	sar authorizationv1.SubjectAccessReviewInterface
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return managementGVR
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update, admissionregistrationv1.Delete}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) *admissionregistrationv1.ValidatingWebhook {
	valWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope)
	valWebhook.FailurePolicy = admission.Ptr(admissionregistrationv1.Ignore)
	return valWebhook
}

// Admit handles the webhook admission request sent to this webhook.
func (v *Validator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	oldCluster, newCluster, err := objectsv3.ClusterOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}

	if newCluster.Spec.FleetWorkspaceName == "" ||
		oldCluster.Spec.FleetWorkspaceName == newCluster.Spec.FleetWorkspaceName {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}

	resp, err := v.sar.Create(request.Context, &v1.SubjectAccessReview{
		Spec: v1.SubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Verb:     "fleetaddcluster",
				Version:  "v3",
				Resource: "fleetworkspaces",
				Group:    "management.cattle.io",
				Name:     newCluster.Spec.FleetWorkspaceName,
			},
			User:   request.UserInfo.Username,
			Groups: request.UserInfo.Groups,
			Extra:  toExtra(request.UserInfo.Extra),
			UID:    request.UserInfo.UID,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, err
	}

	if !resp.Status.Allowed {
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Status:  "Failure",
				Message: resp.Status.Reason,
				Reason:  metav1.StatusReasonUnauthorized,
				Code:    http.StatusUnauthorized,
			},
			Allowed: false,
		}, nil
	}

	return &admissionv1.AdmissionResponse{
		Allowed: true,
	}, nil
}

func toExtra(extra map[string]authenticationv1.ExtraValue) map[string]v1.ExtraValue {
	result := map[string]v1.ExtraValue{}
	for k, v := range extra {
		result[k] = v1.ExtraValue(v)
	}
	return result
}
