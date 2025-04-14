package project

import (
	"encoding/json"
	"fmt"
	"strings"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	ctrlv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/patch"
	"github.com/rancher/wrangler/pkg/name"
	corev1controller "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/storage/names"
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
	namespaceCache    corev1controller.NamespaceCache
	projectCache      ctrlv3.ProjectCache
}

// NewMutator returns a new mutator which mutates projects
func NewMutator(nsCache corev1controller.NamespaceCache, roleTemplateCache ctrlv3.RoleTemplateCache, projectCache ctrlv3.ProjectCache) *Mutator {
	roleTemplateCache.AddIndexer(mutatorCreatorRoleTemplateIndex, creatorRoleTemplateIndexer)
	return &Mutator{
		roleTemplateCache: roleTemplateCache,
		namespaceCache:    nsCache,
		projectCache:      projectCache,
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
		admissionregistrationv1.Update,
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
		project, err = m.admitCreate(project)
		if err != nil {
			return nil, err
		}
	case admissionv1.Update:
		project = m.updateProjectNamespace(project)
	default:
		return nil, fmt.Errorf("operation type %q not handled", request.Operation)
	}
	response := &admissionv1.AdmissionResponse{}
	if err := patch.CreatePatch(request.Object.Raw, project, response); err != nil {
		return nil, fmt.Errorf("failed to create patch: %w", err)
	}
	response.Allowed = true
	return response, nil
}

func (m *Mutator) admitCreate(project *v3.Project) (*v3.Project, error) {
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
	newProject, err = m.createProjectNamespace(newProject)
	if err != nil {
		return nil, fmt.Errorf("failed to create project namespace %s: %w", project.Status.BackingNamespace, err)
	}
	return newProject, nil
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
func (m *Mutator) createProjectNamespace(project *v3.Project) (*v3.Project, error) {
	newProject := project.DeepCopy()
	backingNamespace := ""
	var err error
	// When the project name is empty, that means we want to generate a name for it
	// Name generation happens after mutating webhooks, so in order to have access to the name early
	// for the backing namespace, we need to generate it ourselves
	if project.Name == "" {
		// If err is nil, (meaning "project exists", see below) we need to repeat the generation process to find a project name and backing namespace that isn't taken
		newName := ""
		for err == nil {
			newName = names.SimpleNameGenerator.GenerateName(project.GenerateName)
			_, err = m.projectCache.Get(newProject.Spec.ClusterName, newName)
			if err == nil {
				// A project with this name already exists. Generate a new name.
				continue
			} else if !apierrors.IsNotFound(err) {
				return nil, err
			}

			backingNamespace = name.SafeConcatName(newProject.Spec.ClusterName, strings.ToLower(newName))
			_, err = m.namespaceCache.Get(backingNamespace)

			// If the backing namespace already exists, generate a new project name
			if err != nil && !apierrors.IsNotFound(err) {
				return nil, err
			}
		}
		newProject.Name = newName
	} else {
		backingNamespace = name.SafeConcatName(newProject.Spec.ClusterName, strings.ToLower(newProject.Name))
		_, err = m.namespaceCache.Get(backingNamespace)
		if err == nil {
			return nil, fmt.Errorf("namespace %v already exists", backingNamespace)
		} else if !apierrors.IsNotFound(err) {
			return nil, err
		}
	}

	newProject.Status.BackingNamespace = backingNamespace
	return newProject, nil
}

// updateProjectNamespace fills in BackingNamespace with the project name if it wasn't already set
// this was the naming convention of project namespaces prior to using the BackingNamespace field. Filling
// it here is just to maintain backwards compatibility
func (m *Mutator) updateProjectNamespace(project *v3.Project) *v3.Project {
	if project.Status.BackingNamespace != "" {
		return project
	}
	newProject := project.DeepCopy()
	newProject.Status.BackingNamespace = newProject.Name
	return newProject
}
