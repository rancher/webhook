// Package namespace holds the Admitters and Validator for webhook validation of requests modifying namespace objects.
package namespace

import (
	"github.com/rancher/webhook/pkg/admission"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

var projectsGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "projects",
}

// Validator validates the namespace admission request.
type Validator struct {
	deleteNamespaceAdmitter    deleteNamespaceAdmitter
	psaAdmitter                psaLabelAdmitter
	projectNamespaceAdmitter   projectNamespaceAdmitter
	requestWithinLimitAdmitter requestLimitAdmitter
}

// NewValidator returns a new validator used for validation of namespace requests.
func NewValidator(sar authorizationv1.SubjectAccessReviewInterface) *Validator {
	return &Validator{
		deleteNamespaceAdmitter: deleteNamespaceAdmitter{},
		psaAdmitter: psaLabelAdmitter{
			sar: sar,
		},
		projectNamespaceAdmitter: projectNamespaceAdmitter{
			sar: sar,
		},
		requestWithinLimitAdmitter: requestLimitAdmitter{},
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
func (v *Validator) Operations() []admissionv1.OperationType {
	return []admissionv1.OperationType{
		admissionv1.Update,
		admissionv1.Create,
		admissionv1.Delete,
	}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionv1.WebhookClientConfig) []admissionv1.ValidatingWebhook {
	// Note that namespaces are actually CLUSTER scoped

	// standardWebhook validates all operations specified by (*Validator).Operations() other than the create operation on all namespaces.
	standardWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionv1.ClusterScope, []admissionv1.OperationType{admissionv1.Update})

	// Default configuration for all create operations except those belonging to the kube-system namespace.
	createWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionv1.ClusterScope, []admissionv1.OperationType{admissionv1.Create})
	createWebhook.Name = admission.CreateWebhookName(v, "create-non-kubesystem")
	createWebhook.NamespaceSelector = &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      corev1.LabelMetadataName,
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   []string{"kube-system"},
			},
		},
	}

	// kubeSystemOnlyWebhook is a separate webhook configuration that routes to this handler only if the namespace is equal to kube-system.
	// This configuration differs from above because it allows create request to go through while the webhook is down if and only if the namespace is kube-system.
	kubeSystemCreateWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionv1.ClusterScope, []admissionv1.OperationType{admissionv1.Create})
	kubeSystemCreateWebhook.Name = admission.CreateWebhookName(v, "create-kubesystem-only")
	kubeSystemCreateWebhook.NamespaceSelector = &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      corev1.LabelMetadataName,
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"kube-system"},
			},
		},
	}
	kubeSystemCreateWebhook.FailurePolicy = admission.Ptr(admissionv1.Ignore)

	deleteNamespaceWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionv1.ClusterScope, []admissionv1.OperationType{admissionv1.Delete})
	deleteNamespaceWebhook.Name = admission.CreateWebhookName(v, "delete-namespace")
	deleteNamespaceWebhook.NamespaceSelector = &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      corev1.LabelMetadataName,
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{"fleet-local", "local"},
			},
		},
	}

	return []admissionv1.ValidatingWebhook{*deleteNamespaceWebhook, *standardWebhook, *createWebhook, *kubeSystemCreateWebhook}
}

// Admitters returns the psaAdmitter and the projectNamespaceAdmitter for namespaces.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.psaAdmitter, &v.projectNamespaceAdmitter, &v.requestWithinLimitAdmitter, &v.deleteNamespaceAdmitter}
}
