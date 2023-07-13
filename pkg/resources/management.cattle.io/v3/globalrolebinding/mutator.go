package globalrolebinding

import (
	"errors"
	"fmt"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/patch"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/trace"
)

const grbVersion = "cleanup.cattle.io/grbUpgradeCluster"

// Mutator implements admission.MutatingAdmissionWebhook.
type Mutator struct {
	globalRoles v3.GlobalRoleCache
}

// NewMutator returns a new mutator for GlobalRoleBindings.
func NewMutator(grCache v3.GlobalRoleCache) *Mutator {
	return &Mutator{
		globalRoles: grCache,
	}
}

// GVR returns the GroupVersionKind for this CRD.
func (m *Mutator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this mutator.
func (m *Mutator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create}
}

// MutatingWebhook returns the MutatingWebhook used for this CRD.
func (m *Mutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.MutatingWebhook {
	mutatingWebhook := admission.NewDefaultMutatingWebhook(m, clientConfig, admissionregistrationv1.ClusterScope, m.Operations())
	return []admissionregistrationv1.MutatingWebhook{*mutatingWebhook}
}

// Admit handles the webhook admission request sent to this webhook.
// If this function is called without NewMutator(..) calls will panic.
func (m *Mutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("GlobalRoleBinding Mutator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	newGRB, err := objectsv3.GlobalRoleBindingFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get RoleTemplate from request: %w", err)
	}
	if newGRB.Annotations == nil {
		newGRB.Annotations = map[string]string{}
	}
	newGRB.Annotations[grbVersion] = "true"

	err = m.addOwnerReference(newGRB)
	if err != nil {
		if errors.As(err, admission.Ptr(&field.Error{})) {
			return admission.ResponseBadRequest(err.Error()), nil
		}
		return nil, fmt.Errorf("failed to add owner reference: %w", err)
	}

	response := &admissionv1.AdmissionResponse{}
	if err := patch.CreatePatch(request.Object.Raw, newGRB, response); err != nil {
		return nil, fmt.Errorf("failed to create patch: %w", err)
	}
	response.Allowed = true
	return response, nil
}

// addOwnerReference ensures that a GlobalRoleBinding will be deleted when the role it references is deleted.
func (m *Mutator) addOwnerReference(newGRB *apisv3.GlobalRoleBinding) error {
	globalRole, err := m.globalRoles.Get(newGRB.GlobalRoleName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return field.NotFound(field.NewPath("globalrolebinding", "globalRoleName"), newGRB.Name)
		}
		return fmt.Errorf("failed to get referenced globalRole: %w", err)
	}
	ownerReference := v1.OwnerReference{
		APIVersion: globalRole.APIVersion,
		Kind:       globalRole.Kind,
		Name:       globalRole.Name,
		UID:        globalRole.UID,
	}
	newGRB.OwnerReferences = append(newGRB.OwnerReferences, ownerReference)
	return nil
}
