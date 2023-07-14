package project

import (
	"fmt"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/data/convert"
	corev1controllers "github.com/rancher/wrangler/pkg/generated/controllers/core/v1"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/kubelet/util/format"
	"k8s.io/utils/trace"
)

const (
	systemProjectLabel = "authz.management.cattle.io/system-project"
)

// Validator implements admission.ValidatingAdmissionWebhook.
type Validator struct {
	admitter admitter
}

// NewValidator returns a project validator.
func NewValidator(namespaceCache corev1controllers.NamespaceCache) *Validator {
	return &Validator{
		admitter{
			namespaceCache: namespaceCache,
		},
	}
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
		admissionregistrationv1.Update,
		admissionregistrationv1.Delete,
	}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	validatingWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope, v.Operations())
	return []admissionregistrationv1.ValidatingWebhook{*validatingWebhook}
}

// Admitters returns the admitter objects used to validate secrets.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
	namespaceCache corev1controllers.NamespaceCache
}

// Admit handles the webhook admission request sent to this webhook.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("project Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldProject, newProject, err := objectsv3.ProjectOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get old and new projects from request: %w", err)
	}

	if request.Operation == admissionv1.Delete {
		return a.admitDelete(oldProject)
	}
	return a.admitCreateOrUpdate(oldProject, newProject)
}

func (a *admitter) admitDelete(project *v3.Project) (*admissionv1.AdmissionResponse, error) {
	if project.Labels[systemProjectLabel] == "true" {
		return admission.ResponseBadRequest("System Project cannot be deleted"), nil
	}
	return admission.ResponseAllowed(), nil
}

func (a *admitter) admitCreateOrUpdate(oldProject, newProject *v3.Project) (*admissionv1.AdmissionResponse, error) {
	projectQuota := newProject.Spec.ResourceQuota
	nsQuota := newProject.Spec.NamespaceDefaultResourceQuota
	if projectQuota == nil && nsQuota == nil {
		return admission.ResponseAllowed(), nil
	}
	if projectQuota == nil && nsQuota != nil {
		return admission.ResponseBadRequest("field resourceQuota is required when namespaceDefaultResourceQuota is set"), nil
	}
	if projectQuota != nil && nsQuota == nil {
		return admission.ResponseBadRequest("field namespaceDefaultResourceQuota is required when resourceQuota is set"), nil
	}

	projectQuotaLimitMap, err := convert.EncodeToMap(projectQuota.Limit)
	if err != nil {
		return nil, fmt.Errorf("failed to decode project quota limit: %w", err)
	}
	nsQuotaLimitMap, err := convert.EncodeToMap(nsQuota.Limit)
	if err != nil {
		return nil, fmt.Errorf("failed to decode namespace default quota limit: %w", err)
	}
	if len(projectQuotaLimitMap) != len(nsQuotaLimitMap) {
		return admission.ResponseBadRequest("resource quota and namespace default quota do not have the same resources defined"), nil
	}
	for k := range projectQuotaLimitMap {
		if _, ok := nsQuotaLimitMap[k]; !ok {
			return admission.ResponseBadRequest(fmt.Sprintf("missing namespace default for resource %s defined on resourceQuota", k)), nil
		}
	}
	err = a.checkQuotaRequest(&nsQuota.Limit, &projectQuota.Limit, oldProject)
	if err != nil {
		return admission.ResponseBadRequest(err.Error()), nil
	}
	return admission.ResponseAllowed(), nil
}

func (a *admitter) checkQuotaRequest(newNSQuotaLimit, newProjectQuotaLimit *v3.ResourceQuotaLimit, oldProject *v3.Project) error {
	isFit, exceeded, err := IsQuotaFit(newNSQuotaLimit, []*v3.ResourceQuotaLimit{}, newProjectQuotaLimit)
	if err != nil {
		return err
	}
	if !isFit {
		return fmt.Errorf("namespace default quota limit exceeds project limit on fields: %s", format.ResourceList(exceeded))
	}

	if oldProject == nil || oldProject.Spec.ResourceQuota == nil {
		return nil
	}

	// check if fields were added or removed
	// and update project's namespaces accordingly
	defaultQuotaLimitMap, err := convert.EncodeToMap(newNSQuotaLimit)
	if err != nil {
		return err
	}

	usedQuotaLimitMap := map[string]interface{}{}
	if oldProject.Spec.ResourceQuota != nil {
		usedQuotaLimitMap, err = convert.EncodeToMap(oldProject.Spec.ResourceQuota.UsedLimit)
		if err != nil {
			return err
		}
	}

	limitToAdd := map[string]interface{}{}
	limitToRemove := map[string]interface{}{}
	for key, value := range defaultQuotaLimitMap {
		if _, ok := usedQuotaLimitMap[key]; !ok {
			limitToAdd[key] = value
		}
	}

	for key, value := range usedQuotaLimitMap {
		if _, ok := defaultQuotaLimitMap[key]; !ok {
			limitToRemove[key] = value
		}
	}

	// check that used quota is not bigger than the project quota
	for key := range limitToRemove {
		delete(usedQuotaLimitMap, key)
	}

	usedLimit := &v3.ResourceQuotaLimit{}
	err = convert.ToObj(usedQuotaLimitMap, usedLimit)
	if err != nil {
		return err
	}

	isFit, exceeded, err = IsQuotaFit(usedLimit, []*v3.ResourceQuotaLimit{}, newProjectQuotaLimit)
	if err != nil {
		return err
	}
	if !isFit {
		return fmt.Errorf("resourceQuota is below the used limit on fields: %s", format.ResourceList(exceeded))
	}

	if len(limitToAdd) == 0 && len(limitToRemove) == 0 {
		return nil
	}

	// check if default quota is enough to set on namespaces
	toAppend := &v3.ResourceQuotaLimit{}
	if err := convert.ToObj(limitToAdd, toAppend); err != nil {
		return err
	}
	mu := GetProjectLock(oldProject.Name)
	mu.Lock()
	defer mu.Unlock()

	namespaces, err := a.namespaceCache.List(labels.Set(map[string]string{"field.cattle.io/projectId": oldProject.Name}).AsSelector())
	if err != nil {
		return err
	}
	namespacesCount := len(namespaces)
	var nsLimits []*v3.ResourceQuotaLimit
	for i := 0; i < namespacesCount; i++ {
		nsLimits = append(nsLimits, toAppend)
	}

	isFit, exceeded, err = IsQuotaFit(&v3.ResourceQuotaLimit{}, nsLimits, newProjectQuotaLimit)
	if err != nil {
		return err
	}
	if !isFit {
		return fmt.Errorf("exceeds project limit on fields %s when applied to all namespaces in the project", format.ResourceList(exceeded))
	}
	return nil
}
