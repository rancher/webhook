package clusterroletemplatebinding

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"strings"

	"github.com/rancher/webhook/pkg/admission"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/patch"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

// Mutator implements admission.MutatingAdmissionWebhook.
type Mutator struct{}

// NewMutator returns a new mutator for ClusterRoleTemplateBindings.
func NewMutator() *Mutator {
	return &Mutator{}
}

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
func (m *Mutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("ClusterRoleTemplateBinding Mutator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	if request.Operation != admissionv1.Create {
		return &admissionv1.AdmissionResponse{Allowed: true}, nil
	}

	crtb, err := objectsv3.ClusterRoleTemplateBindingFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s from request: %w", gvr.Resource, err)
	}

	// Only mutate when generateName is in use: name must be empty and generateName must be set.
	// This ensures we never overwrite a name explicitly provided by the caller.
	if crtb.Name != "" {
		return &admissionv1.AdmissionResponse{Allowed: true}, nil
	}
	if crtb.GenerateName == "" {
		return admission.ResponseBadRequest("metadata.name and metadata.generateName are both empty"), nil
	}

	subject := getSubject(crtb.UserPrincipalName, crtb.UserName, crtb.GroupPrincipalName, crtb.GroupName)
	if subject == "" {
		return admission.ResponseBadRequest("no subject found: one of userPrincipalName, userName, groupPrincipalName, or groupName must be set"), nil
	}

	crtb.Name = GenerateDeterministicName(crtb.GenerateName, subject, crtb.RoleTemplateName, crtb.ClusterName)
	crtb.GenerateName = ""

	response := &admissionv1.AdmissionResponse{}
	if err := patch.CreatePatch(request.Object.Raw, crtb, response); err != nil {
		return nil, fmt.Errorf("failed to create patch: %w", err)
	}
	response.Allowed = true
	return response, nil
}

// getSubject returns the binding subject using the following priority:
// UserPrincipalName > UserName > GroupPrincipalName > GroupName.
func getSubject(userPrincipalName, userName, groupPrincipalName, groupName string) string {
	switch {
	case userPrincipalName != "":
		return userPrincipalName
	case userName != "":
		return userName
	case groupPrincipalName != "":
		return groupPrincipalName
	case groupName != "":
		return groupName
	default:
		return ""
	}
}

// GenerateDeterministicName computes a deterministic resource name from the given prefix and
// binding content. The name is: prefix + lowercase(base32(sha256(subject/roleTemplateName/clusterName))[:10]).
// This produces names that are valid K8s resource names and ensures that two identical binding
// requests yield the same name, causing the API server to reject the second with a 409 Conflict.
func GenerateDeterministicName(prefix, subject, roleTemplateName, clusterName string) string {
	hash := sha256.Sum256([]byte(subject + "/" + roleTemplateName + "/" + clusterName))
	encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])
	suffix := strings.ToLower(encoded[:10])
	return prefix + suffix
}
