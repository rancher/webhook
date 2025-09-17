package feature

import (
	"fmt"
	"net/http"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
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
type Validator struct {
	admitter admitter
}

// NewValidator returns a new validator for features.
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
	valWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope, v.Operations())
	valWebhook.FailurePolicy = admission.Ptr(admissionregistrationv1.Ignore)
	return []admissionregistrationv1.ValidatingWebhook{*valWebhook}
}

// Admitters returns the admitter objects used to validate features.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
	//ruleResolver validation.AuthorizationRuleResolver -- not used?
}

// Admit handles the webhook admission request sent to this webhook.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("featureValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldFeature, newFeature, err := objectsv3.FeatureOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}

	if !isUpdateAllowed(oldFeature, newFeature) {
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

// isUpdateAllowed checks that the new value does not change on spec unless it's equal to the lockedValue,
// or lockedValue is nil.
func isUpdateAllowed(oldFeature, newFeature *v3.Feature) bool {
	if oldFeature == nil || newFeature == nil {
		return false
	}
	if newFeature.Status.LockedValue == nil {
		return true
	}
	if oldFeature.Spec.Value == nil && newFeature.Spec.Value == nil {
		return true
	}
	if oldFeature.Spec.Value != nil && newFeature.Spec.Value != nil && *oldFeature.Spec.Value == *newFeature.Spec.Value {
		return true
	}
	if newFeature.Spec.Value != nil && *newFeature.Spec.Value == *newFeature.Status.LockedValue {
		return true
	}
	return false
}
