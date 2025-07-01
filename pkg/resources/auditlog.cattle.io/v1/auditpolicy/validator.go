package auditpolicy

import (
	"errors"
	"fmt"
	"regexp"

	jsonpath "github.com/rancher/jsonpath/pkg"
	auditlogv1 "github.com/rancher/rancher/pkg/apis/auditlog.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	v1 "github.com/rancher/webhook/pkg/generated/objects/auditlog.cattle.io/v1"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

var gvr = schema.GroupVersionResource{
	Group:    auditlogv1.SchemeGroupVersion.Group,
	Version:  auditlogv1.SchemeGroupVersion.Version,
	Resource: "auditpolicies",
}

var _ admission.ValidatingAdmissionHandler = &validator{}

func NewValidator() admission.ValidatingAdmissionHandler {
	return &validator{}
}

type validator struct {
}

// Admitters implements admission.ValidatingAdmissionHandler.
func (v *validator) Admitters() []admission.Admitter {
	return []admission.Admitter{
		&admitter{},
	}
}

// GVR implements admission.ValidatingAdmissionHandler.
func (v *validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations implements admission.ValidatingAdmissionHandler.
func (v *validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
		admissionregistrationv1.Update,
	}
}

// ValidatingWebhook implements admission.ValidatingAdmissionHandler.
func (v *validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{
		*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope, v.Operations()),
	}
}

type admitter struct {
}

func (a *admitter) Admit(req *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if req.Operation != admissionv1.Create && req.Operation != admissionv1.Update {
		return admission.ResponseAllowed(), nil
	}

	policy, err := v1.AuditPolicyFromRequest(&req.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get AuditPolicy from request: %w", err)
	}

	path := field.NewPath("auditpolicy", "spec")

	var fieldErr *field.Error
	if err := a.validateFields(policy, path); err != nil {
		if errors.As(err, &fieldErr) {
			return admission.ResponseBadRequest(fieldErr.Error()), nil
		}

		return nil, fmt.Errorf("failed to validate fields on AuditPolicy")
	}

	return nil, fmt.Errorf("nyi")
}

func (a *admitter) validateFields(policy *auditlogv1.AuditPolicy, path *field.Path) error {
	if policy.Spec.Verbosity.Level < 0 || policy.Spec.Verbosity.Level > 3 {
		return field.Invalid(path.Child("verbosity", "level"), policy.Spec.Verbosity.Level, ".spec.verbosity.level must be >= 0 or <= 3")
	}

	for i, filter := range policy.Spec.Filters {
		path := path.Child("filters").Index(i)

		if filter.Action != auditlogv1.FilterActionAllow && filter.Action != auditlogv1.FilterActionDeny {
			return field.NotSupported(path, filter.Action, []string{string(auditlogv1.FilterActionAllow), string(auditlogv1.FilterActionDeny)})
		}

		if _, err := regexp.Compile(filter.RequestURI); err != nil {
			return field.Invalid(path, filter.RequestURI, err.Error())
		}
	}

	for i, redaction := range policy.Spec.AdditionalRedactions {
		path := path.Child("additionalRedactions").Index(i)

		for j, header := range redaction.Headers {
			path := path.Child("headers").Index(j)

			if _, err := regexp.Compile(header); err != nil {
				return field.Invalid(path, header, err.Error())
			}
		}

		for j, jp := range redaction.Paths {
			path := path.Child("paths").Index(j)

			if _, err := jsonpath.Parse(jp); err != nil {
				return field.Invalid(path, jp, err.Error())
			}
		}
	}

	return nil
}
