package project

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	controllerv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/data/convert"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/trace"
)

const (
	systemProjectLabel  = "authz.management.cattle.io/system-project"
	projectQuotaField   = "resourceQuota"
	clusterNameField    = "clusterName"
	namespaceQuotaField = "namespaceDefaultResourceQuota"
	containerLimitField = "containerDefaultResourceLimit"
)

var projectSpecFieldPath = field.NewPath("project").Child("spec")

// Validator implements admission.ValidatingAdmissionWebhook.
type Validator struct {
	admitter admitter
}

// NewValidator returns a project validator.
func NewValidator(clusterCache controllerv3.ClusterCache) *Validator {
	return &Validator{
		admitter: admitter{
			clusterCache: clusterCache,
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
	clusterCache controllerv3.ClusterCache
}

// Admit handles the webhook admission request sent to this webhook.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("project Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldProject, newProject, err := objectsv3.ProjectOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get old and new projects from request: %w", err)
	}

	switch request.Operation {
	case admissionv1.Create:
		return a.admitCreate(newProject)
	case admissionv1.Update:
		return a.admitUpdate(oldProject, newProject)
	case admissionv1.Delete:
		return a.admitDelete(oldProject)
	default:
		return nil, admission.ErrUnsupportedOperation
	}
}

func (a *admitter) admitDelete(project *v3.Project) (*admissionv1.AdmissionResponse, error) {
	if project.Labels[systemProjectLabel] == "true" {
		return admission.ResponseBadRequest("System Project cannot be deleted"), nil
	}
	return admission.ResponseAllowed(), nil
}

func (a *admitter) admitCreate(project *v3.Project) (*admissionv1.AdmissionResponse, error) {
	fieldErr, err := a.checkClusterExists(project)
	if err != nil {
		return nil, fmt.Errorf("error checking cluster name: %w", err)
	}
	if fieldErr != nil {
		return admission.ResponseBadRequest(fieldErr.Error()), nil
	}
	return a.admitCommonCreateUpdate(nil, project)
}

func (a *admitter) admitUpdate(oldProject, newProject *v3.Project) (*admissionv1.AdmissionResponse, error) {
	if oldProject.Spec.ClusterName != newProject.Spec.ClusterName {
		fieldErr := field.Invalid(projectSpecFieldPath.Child(clusterNameField), newProject.Spec.ClusterName, "field is immutable")
		return admission.ResponseBadRequest(fieldErr.Error()), nil
	}
	return a.admitCommonCreateUpdate(oldProject, newProject)

}

func (a *admitter) admitCommonCreateUpdate(oldProject, newProject *v3.Project) (*admissionv1.AdmissionResponse, error) {
	projectQuota := newProject.Spec.ResourceQuota
	nsQuota := newProject.Spec.NamespaceDefaultResourceQuota
	containerLimit := newProject.Spec.ContainerDefaultResourceLimit
	if fieldErr := a.validateContainerDefaultResourceLimit(containerLimit); fieldErr != nil {
		return admission.ResponseBadRequest(fieldErr.Error()), nil
	}
	if projectQuota == nil && nsQuota == nil {
		return admission.ResponseAllowed(), nil
	}
	fieldErr, err := checkQuotaFields(projectQuota, nsQuota)
	if err != nil {
		return nil, fmt.Errorf("error checking project quota fields: %w", err)
	}
	if fieldErr != nil {
		return admission.ResponseBadRequest(fieldErr.Error()), nil
	}
	fieldErr, err = a.checkQuotaValues(&nsQuota.Limit, &projectQuota.Limit, oldProject)
	if err != nil {
		return nil, fmt.Errorf("error checking quota values: %w", err)
	}
	if fieldErr != nil {
		return admission.ResponseBadRequest(fieldErr.Error()), nil
	}
	return admission.ResponseAllowed(), nil
}

// validateContainerDefaultResourceLimit checks all resource requests and limits.
// It returns a fieldError. If the method is ever changed to also return a regular error, the caller's logic
// needs to be updated to act appropriately based on the kind of error.
func (a *admitter) validateContainerDefaultResourceLimit(limit *v3.ContainerResourceLimit) error {
	if limit == nil {
		return nil
	}
	fieldPath := projectSpecFieldPath.Child(containerLimitField)
	requestsCPU, err := parseResource(limit.RequestsCPU)
	if err != nil {
		return field.Invalid(fieldPath, limit.RequestsCPU, fmt.Sprintf("failed to parse container default requested CPU: %s", err))
	}
	limitsCPU, err := parseResource(limit.LimitsCPU)
	if err != nil {
		return field.Invalid(fieldPath, limit.LimitsCPU, fmt.Sprintf("failed to parse container default CPU limit: %s", err))
	}
	requestsMemory, err := parseResource(limit.RequestsMemory)
	if err != nil {
		return field.Invalid(fieldPath, limit.RequestsMemory, fmt.Sprintf("failed to parse container default requested memory: %s", err))
	}
	limitsMemory, err := parseResource(limit.LimitsMemory)
	if err != nil {
		return field.Invalid(fieldPath, limit.LimitsMemory, fmt.Sprintf("failed to parse container default memory limit: %s", err))
	}
	if requestsCPU != nil && limitsCPU != nil && requestsCPU.Cmp(*limitsCPU) > 0 {
		fieldErr := field.Invalid(fieldPath, limit, fmt.Sprintf("requested CPU %s is greater than limit %s", limit.RequestsCPU, limit.LimitsCPU))
		err = errors.Join(err, fieldErr)
	}
	if requestsMemory != nil && limitsMemory != nil && requestsMemory.Cmp(*limitsMemory) > 0 {
		fieldErr := field.Invalid(fieldPath, limit, fmt.Sprintf("requested memory %s is greater than limit %s", limit.RequestsMemory, limit.LimitsMemory))
		err = errors.Join(err, fieldErr)
	}
	return err
}

func (a *admitter) checkClusterExists(project *v3.Project) (*field.Error, error) {
	if project.Spec.ClusterName == "" {
		return field.Required(projectSpecFieldPath.Child(clusterNameField), "clusterName is required"), nil
	}
	if project.Spec.ClusterName != project.Namespace {
		return field.Invalid(projectSpecFieldPath.Child(clusterNameField), project.Spec.ClusterName, "clusterName and project namespace must match"), nil
	}
	cluster, err := a.clusterCache.Get(project.Spec.ClusterName)
	clusterNotFoundErr := field.Invalid(projectSpecFieldPath.Child(clusterNameField), project.Spec.ClusterName, "cluster not found")
	if err != nil {
		if apierrors.IsNotFound(err) {
			return clusterNotFoundErr, nil
		}
		return nil, fmt.Errorf("unable to verify cluster %s exists: %w", project.Spec.ClusterName, err)
	}
	if cluster == nil {
		return clusterNotFoundErr, nil
	}
	return nil, nil
}

func checkQuotaFields(projectQuota *v3.ProjectResourceQuota, nsQuota *v3.NamespaceResourceQuota) (*field.Error, error) {
	if projectQuota == nil && nsQuota != nil {
		return field.Required(projectSpecFieldPath.Child(projectQuotaField), fmt.Sprintf("required when %s is set", namespaceQuotaField)), nil
	}
	if projectQuota != nil && nsQuota == nil {
		return field.Required(projectSpecFieldPath.Child(namespaceQuotaField), fmt.Sprintf("required when %s is set", projectQuotaField)), nil
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
		return field.Invalid(projectSpecFieldPath.Child(projectQuotaField), projectQuota, "resource quota and namespace default quota do not have the same resources defined"), nil
	}
	for k := range projectQuotaLimitMap {
		if _, ok := nsQuotaLimitMap[k]; !ok {
			return field.Invalid(projectSpecFieldPath.Child(namespaceQuotaField), nsQuota, fmt.Sprintf("missing namespace default for resource %s defined on %s", k, projectQuotaField)), nil
		}
	}
	return nil, nil
}

func (a *admitter) checkQuotaValues(nsQuota, projectQuota *v3.ResourceQuotaLimit, oldProject *v3.Project) (*field.Error, error) {
	// check quota on new project
	fieldErr, err := namespaceQuotaFits(nsQuota, projectQuota)
	if err != nil || fieldErr != nil {
		return fieldErr, err
	}

	// if there is no old project or no quota on the old project, no further validation needed
	if oldProject == nil || oldProject.Spec.ResourceQuota == nil {
		return nil, nil
	}

	// check quota relative to used quota
	return usedQuotaFits(&oldProject.Spec.ResourceQuota.UsedLimit, projectQuota)
}

func namespaceQuotaFits(namespaceQuota, projectQuota *v3.ResourceQuotaLimit) (*field.Error, error) {
	namespaceQuotaResourceList, err := convertLimitToResourceList(namespaceQuota)
	if err != nil {
		return nil, err
	}
	projectQuotaResourceList, err := convertLimitToResourceList(projectQuota)
	if err != nil {
		return nil, err
	}
	fits, exceeded := quotaFits(namespaceQuotaResourceList, projectQuotaResourceList)
	if !fits {
		return field.Forbidden(projectSpecFieldPath.Child(namespaceQuotaField), fmt.Sprintf("namespace default quota limit exceeds project limit on fields: %s", formatResourceList(exceeded))), nil
	}
	return nil, nil
}

func usedQuotaFits(usedQuota, projectQuota *v3.ResourceQuotaLimit) (*field.Error, error) {
	usedQuotaResourceList, err := convertLimitToResourceList(usedQuota)
	if err != nil {
		return nil, err
	}
	projectQuotaResourceList, err := convertLimitToResourceList(projectQuota)
	if err != nil {
		return nil, err
	}
	fits, exceeded := quotaFits(usedQuotaResourceList, projectQuotaResourceList)
	if !fits {
		return field.Forbidden(projectSpecFieldPath.Child(projectQuotaField), fmt.Sprintf("resourceQuota is below the used limit on fields: %s", formatResourceList(exceeded))), nil
	}
	return nil, nil
}

// directly copied from https://github.com/kubernetes/kubernetes/blob/a66aad2d80dacc70025f95a8f97d2549ebd3208c/pkg/kubelet/util/format/resources.go
func formatResourceList(resources v1.ResourceList) string {
	resourceStrings := make([]string, 0, len(resources))
	for key, value := range resources {
		resourceStrings = append(resourceStrings, fmt.Sprintf("%v=%v", key, value.String()))
	}
	// sort the results for consistent log output
	sort.Strings(resourceStrings)
	return strings.Join(resourceStrings, ",")
}

func parseResource(s string) (*resource.Quantity, error) {
	if s == "" {
		// Upstream `resource.ParseQuantity` will return an error when given an empty string.
		return nil, nil
	}
	q, err := resource.ParseQuantity(s)
	return &q, err
}
