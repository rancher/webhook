package roletemplate

import (
	"encoding/json"
	"fmt"
	"reflect"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/patch"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

// Mutator implements admission.MutatingAdmissionWebhook.
type Mutator struct {
}

// NewMutator returns a new mutator for RoleTemplates.
func NewMutator() *Mutator {
	return &Mutator{}
}

// GVR returns the GroupVersionKind for this CRD.
func (m *Mutator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this mutator.
func (m *Mutator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update}
}

// MutatingWebhook returns the MutatingWebhook used for this CRD.
func (m *Mutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.MutatingWebhook {
	mutatingWebhook := admission.NewDefaultMutatingWebhook(m, clientConfig, admissionregistrationv1.ClusterScope, m.Operations())

	return []admissionregistrationv1.MutatingWebhook{*mutatingWebhook}
}

// Admit handles the webhook admission request sent to this webhook.
// If this function is called without NewMutator(..) calls will panic.
func (m *Mutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("RoleTemplate Mutator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	return updateRoleTemplateIfRulesEncodedAreDifferent(request)
}

// updateRoleTemplateIfRulesEncodedAreDifferent applies a patch to the response to ensure that the RoleTemplate is encoded
// when the encoded rules differ from the non-encoded rules. This disparity was causing the following issue:
// A RoleTemplate created with an empty list of rules would lead to the creation of a corresponding ClusterRole with a nil list.
// When Rancher synchronizes RoleTemplates and ClusterRoles, it detects that an empty list is not equal to a nil list and
// attempts to update the ClusterRole.
func updateRoleTemplateIfRulesEncodedAreDifferent(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	rt, err := objectsv3.RoleTemplateFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s from request: %w", gvr.Resource, err)
	}
	rtEncodedBytes, err := json.Marshal(rt)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal roleTemplate: %w", err)
	}
	var rtEncoded v3.RoleTemplate
	err = json.Unmarshal(rtEncodedBytes, &rtEncoded)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal roleTemplate: %w", err)
	}

	response := &admissionv1.AdmissionResponse{}
	if !reflect.DeepEqual(rt.Rules, rtEncoded.Rules) {
		if err := patch.CreatePatch(request.Object.Raw, rtEncoded, response); err != nil {
			return nil, fmt.Errorf("failed to create patch: %w", err)
		}
	}
	response.Allowed = true

	return response, nil
}
