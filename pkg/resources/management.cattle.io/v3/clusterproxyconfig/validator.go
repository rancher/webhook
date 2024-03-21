package clusterproxyconfig

import (
	"fmt"
	"net/http"

	"github.com/rancher/webhook/pkg/admission"
	webhookadmission "github.com/rancher/webhook/pkg/admission"
	controllerv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "clusterproxyconfigs",
}

// Validator for validating clusterproxyconfigs.
type Validator struct {
	admitter admitter
}

// NewValidator returns a new validator for clusterproxyconfigs.
func NewValidator(cpsCache controllerv3.ClusterProxyConfigCache) *Validator {
	return &Validator{
		admitter: admitter{
			cpsCache: cpsCache,
		},
	}
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	valWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope, v.Operations())
	valWebhook.FailurePolicy = admission.Ptr(admissionregistrationv1.Fail)
	return []admissionregistrationv1.ValidatingWebhook{*valWebhook}
}

// Admitters returns the admitter objects used to validate clusterproxyconfigs.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
	cpsCache controllerv3.ClusterProxyConfigCache
}

// Admit handles the webhook admission request sent to this webhook.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("clusterProxyConfigValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	cps, err := a.cpsCache.List(request.Namespace, labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch list of existing clusterproxyconfigs for clusterID %s: %w", request.Namespace, err)
	}
	// There can be no more than 1 clusterproxyconfig created per downstream cluster
	if len(cps) > 0 {
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Status:  "Failure",
				Message: fmt.Sprintf("there may only be one clusterproxyconfig object defined per cluster"),
				Reason:  metav1.StatusReasonInvalid,
				Code:    http.StatusConflict,
			},
			Allowed: false,
		}, nil
	}

	return webhookadmission.ResponseAllowed(), nil
}
