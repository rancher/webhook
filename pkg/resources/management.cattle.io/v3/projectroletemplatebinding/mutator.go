package projectroletemplatebinding

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/patch"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

// NewMutator returns a new mutator for ProjectRoleTemplateBindings.
func NewMutator() *Mutator {
	return &Mutator{}
}

// Mutator implements admission.MutatingAdmissionHandler for ProjectRoleTemplateBindings.
// On CREATE, when the generateName pattern is in use (metadata.name is empty), it creates
// a deterministic name derived from the binding's content.
// Two identical concurrent requests will produce the same name, causing the K8s
// API server to reject the second with a 409 Conflict.
//
// When metadata.name is already set (i.e. the client explicitly chose a name), the mutator
// does nothing.
type Mutator struct{}

// GVR returns the GroupVersionResource for this CRD.
func (m *Mutator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this mutator.
func (m *Mutator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create}
}

// MutatingWebhook returns the MutatingWebhook used for this CRD.
func (m *Mutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.MutatingWebhook {
	mutatingWebhook := admission.NewDefaultMutatingWebhook(m, clientConfig, admissionregistrationv1.NamespacedScope, m.Operations())
	return []admissionregistrationv1.MutatingWebhook{*mutatingWebhook}
}

// Admit handles the webhook admission request sent to this webhook.
// On CREATE, when metadata.generateName is set, it computes a deterministic name
// based on a hash of the binding's subject, roleTemplateName, and projectName.
func (m *Mutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("ProjectRoleTemplateBinding Mutator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	prtb, err := objectsv3.ProjectRoleTemplateBindingFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s from request: %w", gvr.Resource, err)
	}

	// Skip when the client explicitly set a name.
	if prtb.Name != "" {
		return &admissionv1.AdmissionResponse{Allowed: true}, nil
	}

	// Reject if neither name nor generateName is set.
	if prtb.GenerateName == "" {
		return admission.ResponseBadRequest("metadata.name or metadata.generateName must be set"), nil
	}

	subject := resolveSubject(prtb)
	if subject == "" {
		// No subject found; let the validating webhook handle the error.
		return &admissionv1.AdmissionResponse{Allowed: true}, nil
	}

	deterministicName := GenerateDeterministicName(prtb.GenerateName, subject, prtb.RoleTemplateName, prtb.ProjectName)
	prtb.Name = deterministicName
	prtb.GenerateName = ""

	response := &admissionv1.AdmissionResponse{}
	if err := patch.CreatePatch(request.Object.Raw, prtb, response); err != nil {
		return nil, fmt.Errorf("failed to create patch: %w", err)
	}
	response.Allowed = true
	return response, nil
}

// resolveSubject determines the binding subject using the same priority order as the
// validating webhook: UserPrincipalName → UserName → GroupPrincipalName → GroupName → ServiceAccount.
func resolveSubject(prtb *apisv3.ProjectRoleTemplateBinding) string {
	switch {
	case prtb.UserPrincipalName != "":
		return prtb.UserPrincipalName
	case prtb.UserName != "":
		return prtb.UserName
	case prtb.GroupPrincipalName != "":
		return prtb.GroupPrincipalName
	case prtb.GroupName != "":
		return prtb.GroupName
	case prtb.ServiceAccount != "":
		return prtb.ServiceAccount
	default:
		return ""
	}
}

// GenerateDeterministicName computes a deterministic PRTB name from the given prefix, subject,
// roleTemplateName, and projectName. The formula is:
//
//	prefix + lowercase(base32(sha256(subject + "/" + roleTemplateName + "/" + projectName))[:10])
//
// WARNING: Changing this formula will break idempotency for existing clients. Treat the
// output format as a stable API contract.
func GenerateDeterministicName(prefix, subject, roleTemplateName, projectName string) string {
	input := subject + "/" + roleTemplateName + "/" + projectName
	hash := sha256.Sum256([]byte(input))
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])
	// Take first 10 characters and lowercase.
	suffix := strings.ToLower(encoded[:10])
	return prefix + suffix
}
