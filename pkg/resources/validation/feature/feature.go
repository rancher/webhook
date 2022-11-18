package feature

import (
	"fmt"
	"net/http"

	"github.com/rancher/webhook/pkg/admission"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "features",
}

// Validator for validating features.
type Validator struct{}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Update}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) *admissionregistrationv1.ValidatingWebhook {
	valWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope)
	valWebhook.FailurePolicy = admission.Ptr(admissionregistrationv1.Ignore)
	return valWebhook
}

// Admit handles the webhook admission request sent to this webhook.
func (v *Validator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("featureValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldFeature, newFeature, err := objectsv3.FeatureOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}

	if !isValidFeatureValue(newFeature.Status.LockedValue, oldFeature.Spec.Value, newFeature.Spec.Value) {
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Status:  "Failure",
				Message: fmt.Sprintf("feature flag cannot be changed from current value: %v", *newFeature.Status.LockedValue),
				Reason:  metav1.StatusReasonInvalid,
				Code:    http.StatusBadRequest,
			},
			Allowed: false,
		}, nil
	}

	return &admissionv1.AdmissionResponse{
		Allowed: true,
	}, nil
}

// isValidFeatureValue checks that desired value does not change value on spec unless lockedValue
// is nil or it is equal to the lockedValue.
func isValidFeatureValue(lockedValue *bool, oldSpecValue *bool, desiredSpecValue *bool) bool {
	if lockedValue == nil {
		return true
	}

	if oldSpecValue == nil && desiredSpecValue == nil {
		return true
	}

	if oldSpecValue != nil && desiredSpecValue != nil && *oldSpecValue == *desiredSpecValue {
		return true
	}

	if desiredSpecValue != nil && *desiredSpecValue == *lockedValue {
		return true
	}

	return false
}
