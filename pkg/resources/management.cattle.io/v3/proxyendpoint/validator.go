package proxyendpoint

import (
	"strings"

	v4 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	v3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"golang.org/x/net/publicsuffix"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var proxyEndpointGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "proxyendpoints",
}

type Validator struct {
	admitter admitter
}

func NewProxyEndpointValidator() admission.ValidatingAdmissionHandler {
	return &Validator{
		admitter: admitter{},
	}
}

func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope, v.Operations())}
}

func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

func (v *Validator) GVR() schema.GroupVersionResource {
	return proxyEndpointGVR
}

func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update}
}

type admitter struct{}

func (a *admitter) Admit(req *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		return admission.ResponseAllowed(), nil
	}

	endpointFromRequest, err := v3.ProxyEndpointFromRequest(&req.AdmissionRequest)
	if err != nil {
		return admission.ResponseBadRequest("failed to parse ProxyEndpoint from request"), err
	}

	return a.checkRoutes(endpointFromRequest), nil
}

func (a *admitter) checkRoutes(endpoint *v4.ProxyEndpoint) *admissionv1.AdmissionResponse {
	for _, route := range endpoint.Spec.Routes {
		if a.isOverlyBroad(route.Domain) {
			return admission.ResponseBadRequest("domain route cannot be overly broad (e.g., '*', '*.%', '*.<tld>', 'example.%.<tld>', etc.)")
		}
	}
	return admission.ResponseAllowed()
}

// isOverlyBroad checks if the given domain is overly broad wildcard.
// A domain is overly broad if it would match all or most domains under a TLD.
// Examples: "*.com", "*.co.uk", "%.com", "%.co.uk", "%.%.com", "subdomain.%.co.uk"
//
// Wildcard rules:
// - '*' can only appear as the leftmost character (e.g., *.example.com, *test.com)
// - '%' can appear as the leftmost character OR within segments (e.g., %.test.com, example.%.api.com)
func (a *admitter) isOverlyBroad(pattern string) bool {
	if !strings.ContainsAny(pattern, "*%") {
		return false
	}

	// replace wildcards with a valid character so publicsuffix can parse it
	normalized := strings.ReplaceAll(pattern, "*", "z")
	normalized = strings.ReplaceAll(normalized, "%", "z")

	// get the suffix, .com, .co.uk, etc.
	suffix, _ := publicsuffix.PublicSuffix(normalized)

	// identify the label right before the eTLD
	suffixDotCount := strings.Count(suffix, ".")
	labels := strings.Split(pattern, ".")

	// Find the first character for that label
	idx := len(labels) - suffixDotCount - 2

	if idx < 0 {
		return true // Pattern is just a suffix, treat as broad/invalid
	}
	targetLabel := labels[idx]

	// check if that label is a plain wildcard.
	return targetLabel == "*" || targetLabel == "%"
}
