package clusterrolebinding

import (
	"fmt"

	"github.com/rancher/webhook/pkg/admission"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/rbac.authorization.k8s.io/v1"
	"github.com/rancher/webhook/pkg/resources/common"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

const (
	grbOwnerLabel = "authz.management.cattle.io/grb-owner"
)

// Validator implements admission.ValidatingAdmissionHandler.
type Validator struct {
	admitter admitter
}

// NewValidator returns a new validator for clusterrolebindings.
func NewValidator() *Validator {
	return &Validator{
		admitter: admitter{},
	}
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    "rbac.authorization.k8s.io",
		Version:  "v1",
		Resource: "clusterrolebindings",
	}
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{
		admissionregistrationv1.Update,
	}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	webhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope, v.Operations())
	webhook.ObjectSelector = &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      grbOwnerLabel,
				Operator: metav1.LabelSelectorOpExists,
			},
		},
	}

	return []admissionregistrationv1.ValidatingWebhook{*webhook}
}

// Admitters returns the admitter objects used to validate roles.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct{}

// Admit is the entrypoint for the validator. Admit will return an error if it's unable to process the request.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("clusterRolebindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldRoleBinding, newRoleBinding, err := objectsv1.ClusterRoleBindingOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}

	if common.IsModifyingLabel(oldRoleBinding.Labels, newRoleBinding.Labels, grbOwnerLabel) {
		return admission.ResponseBadRequest(fmt.Sprintf("cannot modify or remove label %s", grbOwnerLabel)), nil
	}

	return admission.ResponseAllowed(), nil
}
