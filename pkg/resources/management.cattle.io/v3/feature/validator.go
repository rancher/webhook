package feature

import (
	"fmt"
	"net/http"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
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
func NewValidator(ruleResolver validation.AuthorizationRuleResolver) *Validator {
	return &Validator{
		admitter: admitter{
			ruleResolver: ruleResolver,
		},
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
	ruleResolver validation.AuthorizationRuleResolver
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

	if newFeature.Name == auth.ExternalRulesFeature {
		var rules []rbacv1.PolicyRule
		oldFeatureValue := getEffectiveValue(oldFeature)
		newFeatureValue := getEffectiveValue(newFeature)

		// if the feature value isn't changing, allow it
		if oldFeatureValue == newFeatureValue {
			return &admissionv1.AdmissionResponse{
				Allowed: true,
			}, nil
		}

		if !oldFeatureValue && newFeatureValue {
			// enabling the feature requires the "security-enable" verb
			rules = []rbacv1.PolicyRule{
				{
					Verbs:         []string{"security-enable"},
					APIGroups:     []string{"management.cattle.io"},
					Resources:     []string{"features"},
					ResourceNames: []string{"external-rules"},
				},
			}
		} else {
			// disabling the feature requires administrator permissions
			rules = []rbacv1.PolicyRule{
				{
					Verbs:     []string{"*"},
					APIGroups: []string{"*"},
					Resources: []string{"*"},
				},
			}
		}
		err := auth.ConfirmNoEscalation(request, rules, "", a.ruleResolver)
		if err != nil {
			return admission.ResponseFailedEscalation(fmt.Sprintf("updating the 'external-rules' feature requires admin permissions: %s ", err.Error())), nil
		}
	}

	return &admissionv1.AdmissionResponse{
		Allowed: true,
	}, nil
}

// getEffectiveValue considers a feature's default, value, and locked value to determine
// its effective value.
func getEffectiveValue(obj *v3.Feature) bool {
	val := obj.Status.Default
	if obj.Spec.Value != nil {
		val = *obj.Spec.Value
	}
	if obj.Status.LockedValue != nil {
		val = *obj.Status.LockedValue
	}
	return val
}

// isUpdateAllowed checks that the new value does not change on spec unless it's equal to the lockedValue,
// or lockedValue is nil.
func isUpdateAllowed(old, new *v3.Feature) bool {
	if old == nil || new == nil {
		return false
	}
	if new.Status.LockedValue == nil {
		return true
	}
	if old.Spec.Value == nil && new.Spec.Value == nil {
		return true
	}
	if old.Spec.Value != nil && new.Spec.Value != nil && *old.Spec.Value == *new.Spec.Value {
		return true
	}
	if new.Spec.Value != nil && *new.Spec.Value == *new.Status.LockedValue {
		return true
	}
	return false
}
