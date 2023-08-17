package project

import (
	"encoding/json"
	"fmt"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	ctrlv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/patch"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

const (
	roleTemplatesRequired           = "authz.management.cattle.io/creator-role-bindings"
	indexKey                        = "creatorDefaultUnlocked"
	mutatorCreatorRoleTemplateIndex = "webhook.cattle.io/creator-role-template-index"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "projects",
}

// Mutator implements admission.MutatingAdmissionWebhook.
type Mutator struct {
	roleTemplateCache ctrlv3.RoleTemplateCache
}

// NewMutator returns a new mutator which mutates projects
func NewMutator(roleTemplateCache ctrlv3.RoleTemplateCache) *Mutator {
	roleTemplateCache.AddIndexer(mutatorCreatorRoleTemplateIndex, creatorRoleTemplateIndexer)
	return &Mutator{
		roleTemplateCache: roleTemplateCache,
	}
}

// creatorRoleTemplateIndexer indexes a role template based on whether it's an owner type role template.
func creatorRoleTemplateIndexer(roleTemplate *v3.RoleTemplate) ([]string, error) {
	if roleTemplate.ProjectCreatorDefault && !roleTemplate.Locked {
		return []string{indexKey}, nil
	}
	return nil, nil
}

// GVR returns the GroupVersionKind for this CRD.
func (m *Mutator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this mutator.
func (m *Mutator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
	}
}

// MutatingWebhook returns the MutatingWebhook used for this CRD.
func (m *Mutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.MutatingWebhook {
	mutatingWebhook := admission.NewDefaultMutatingWebhook(m, clientConfig, admissionregistrationv1.NamespacedScope, m.Operations())
	mutatingWebhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNone)
	return []admissionregistrationv1.MutatingWebhook{*mutatingWebhook}
}

// Admit is the entrypoint for the mutator. Admit will return an error if it unable to process the request.
func (m *Mutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if request.DryRun != nil && *request.DryRun {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}

	listTrace := trace.New("project Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	project, err := objectsv3.ProjectFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}
	switch request.Operation {
	case admissionv1.Create:
		return m.admitCreate(project, request)
	default:
		return nil, fmt.Errorf("operation type %q not handled", request.Operation)
	}
}

func (m *Mutator) admitCreate(project *v3.Project, request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	logrus.Debugf("[project-mutation] adding creator-role-bindings to project: %v", project.Name)
	newProject := project.DeepCopy()

	if newProject.Annotations == nil {
		newProject.Annotations = make(map[string]string)
	}
	annotations, err := m.getCreatorRoleTemplateAnnotations()
	if err != nil {
		return nil, fmt.Errorf("failed to add annotation to project %s: %w", project.Name, err)
	}
	newProject.Annotations[roleTemplatesRequired] = annotations
	response := &admissionv1.AdmissionResponse{}
	if err := patch.CreatePatch(request.Object.Raw, newProject, response); err != nil {
		return nil, fmt.Errorf("failed to create patch: %w", err)
	}
	response.Allowed = true
	return response, nil
}

func (m *Mutator) getCreatorRoleTemplateAnnotations() (string, error) {
	roleTemplates, err := m.roleTemplateCache.GetByIndex(mutatorCreatorRoleTemplateIndex, indexKey)
	if err != nil {
		return "", err
	}
	annoMap := make(map[string][]string)
	for _, role := range roleTemplates {
		annoMap["required"] = append(annoMap["required"], role.Name)
	}
	annotations, err := json.Marshal(annoMap)
	if err != nil {
		return "", err
	}
	return string(annotations), nil
}
