package secret

import (
	"fmt"
	"strings"

	"github.com/rancher/webhook/pkg/admission"
	v1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistration "k8s.io/api/admissionregistration/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	projectScopedLabel  = "cattle.io/project-scoped"
	projectIDAnnotation = "field.cattle.io/projectId"
)

func NewProjectScopedValidator() *ProjectScopedValidator {
	return &ProjectScopedValidator{
		admitter: projectScopedAdmitter{},
	}
}

type ProjectScopedValidator struct {
	admitter projectScopedAdmitter
}

func (v *ProjectScopedValidator) GVR() schema.GroupVersionResource {
	return gvr
}

func (v *ProjectScopedValidator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update}
}

func (v *ProjectScopedValidator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	webhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistration.NamespacedScope, v.Operations())
	webhook.Name = admission.CreateWebhookName(v, "project-scoped")
	webhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNone)
	webhook.ObjectSelector = &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      projectScopedLabel,
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"original"},
			},
		},
	}

	return []admissionregistrationv1.ValidatingWebhook{*webhook}
}

func (v *ProjectScopedValidator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

func (v *ProjectScopedValidator) Path() string {
	return "project-scoped-secrets"
}

type projectScopedAdmitter struct {
}

func (a *projectScopedAdmitter) validateUpdate(oldSecret, newSecret *corev1.Secret) error {
	if newSecret.Annotations[projectIDAnnotation] != oldSecret.Annotations[projectIDAnnotation] {
		return fmt.Errorf("annotation %s must be immutable", projectIDAnnotation)
	}
	if newSecret.Labels[projectScopedLabel] != oldSecret.Labels[projectScopedLabel] {
		return fmt.Errorf("label %s must be immutable", projectScopedLabel)
	}
	return nil
}

func (a *projectScopedAdmitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if request.Operation == admissionv1.Update {
		oldSecret, newSecret, err := v1.SecretOldAndNewFromRequest(&request.AdmissionRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to read the existing and updated secrets from the request: %w", err)
		}
		if err := a.validateUpdate(oldSecret, newSecret); err != nil {
			return admission.ResponseBadRequest(err.Error()), nil
		}
		return admission.ResponseAllowed(), nil
	}
	secret, err := v1.SecretFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to read the secret from the request: %w", err)
	}
	if err := a.validateCreate(secret); err != nil {
		return admission.ResponseBadRequest(err.Error()), nil
	}
	return admission.ResponseAllowed(), nil
}

func (a *projectScopedAdmitter) validateCreate(secret *corev1.Secret) error {
	id := clusterID(secret.Annotations[projectIDAnnotation])
	if id == "" {
		return fmt.Errorf("cluster ID is missing in the %s annotation", projectIDAnnotation)
	}
	return nil
}

func clusterID(s string) string {
	parts := strings.Split(strings.TrimSpace(s), ":")
	if len(parts) == 0 {
		return ""
	}
	return parts[0]
}
