// Package podsecurityadmissionconfigurationtemplate is used for validating podsecurityadmissionconfigurationtemplate admission requests.
package podsecurityadmissionconfigurationtemplate

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	mgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	provv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	v1 "github.com/rancher/webhook/pkg/generated/controllers/provisioning.cattle.io/v1"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	machinery "k8s.io/apimachinery/pkg/api/validation"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/pod-security-admission/api"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "podsecurityadmissionconfigurationtemplates",
}

// Validator validates the PodSecurityAdmissionConfigurationTemplate admission request.
type Validator struct {
	ManagementClusterCache   v3.ClusterCache
	provisioningClusterCache v1.ClusterCache
}

const (
	byPodSecurityAdmissionConfigurationName = "podSecurityAdmissionConfigurationName"
	rancherPrivilegedPSACTName              = "rancher-privileged"
	rancherRestrictedPSACTName              = "rancher-restricted"
)

// NewValidator returns a validator for PodSecurityAdmissionConfigurationTemplates
func NewValidator(managementCache v3.ClusterCache, provisioningCache v1.ClusterCache) *Validator {
	val := &Validator{
		ManagementClusterCache:   managementCache,
		provisioningClusterCache: provisioningCache,
	}
	val.ManagementClusterCache.AddIndexer(byPodSecurityAdmissionConfigurationName, byPodSecurityAdmissionConfigurationTemplateV3)
	val.provisioningClusterCache.AddIndexer(byPodSecurityAdmissionConfigurationName, byPodSecurityAdmissionConfigurationTemplateV1)
	return val
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	valWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.AllScopes, v.Operations())
	valWebhook.FailurePolicy = admission.Ptr(admissionregistrationv1.Ignore)
	return []admissionregistrationv1.ValidatingWebhook{*valWebhook}
}

func byPodSecurityAdmissionConfigurationTemplateV1(obj *provv1.Cluster) ([]string, error) {
	if obj.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName == "" {
		return nil, nil
	}
	return []string{obj.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName}, nil
}

func byPodSecurityAdmissionConfigurationTemplateV3(obj *mgmtv3.Cluster) ([]string, error) {
	if obj.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName == "" {
		return nil, nil
	}
	return []string{obj.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName}, nil
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Update, admissionregistrationv1.Create, admissionregistrationv1.Delete}
}

// Admit handles the webhook admission request sent to this webhook.
func (v *Validator) Admit(req *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("PodSecurityAdmissionConfigurationTemplate Admit", trace.Field{Key: "user", Value: req.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	resp := &admissionv1.AdmissionResponse{}
	oldTemplate, newTemplate, err := objectsv3.PodSecurityAdmissionConfigurationTemplateOldAndNewFromRequest(&req.AdmissionRequest)
	if err != nil {
		return resp, fmt.Errorf("failed to parse PodSecurityAdmissionConfigurationTemplate object from request:%w", err)
	}

	switch req.Operation {
	case admissionv1.Create, admissionv1.Update:
		err = v.validateConfiguration(newTemplate)
		if err != nil {
			resp.Result = &metav1.Status{
				Status:  "Failure",
				Message: err.Error(),
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusUnprocessableEntity,
			}
			resp.Allowed = false
			break
		}
		resp.Allowed = true
	case admissionv1.Delete:
		// do not allow the default 'restricted' and 'privileged' templates from being deleted
		if oldTemplate.Name == rancherPrivilegedPSACTName || oldTemplate.Name == rancherRestrictedPSACTName {
			resp.Result = &metav1.Status{
				Status:  "Failure",
				Message: fmt.Sprintf("Cannot delete built-in template '%s'", oldTemplate.Name),
				Reason:  metav1.StatusReasonForbidden,
				Code:    http.StatusForbidden,
			}
			resp.Allowed = false
			break
		}

		clustersUsingTemplate, clusterType, err := v.handleDeletion(oldTemplate)
		if err != nil {
			// error encountered with indexer
			resp.Result = &metav1.Status{
				Status:  "Failure",
				Message: err.Error(),
				Reason:  metav1.StatusReasonInternalError,
				Code:    http.StatusInternalServerError,
			}
			resp.Allowed = false
			break
		}

		if clustersUsingTemplate > 0 {
			// template in use, cannot be deleted
			message := fmt.Sprintf("Cannot delete template '%s' as it is being used by %d %s clusters", oldTemplate.Name, clustersUsingTemplate, clusterType)
			if clustersUsingTemplate == 1 {
				message = fmt.Sprintf("Cannot delete template '%s' as it is being used by a %s cluster", oldTemplate.Name, clusterType)
			}
			resp.Result = &metav1.Status{
				Status:  "Failure",
				Message: message,
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			}
			resp.Allowed = false
			break
		}
		resp.Allowed = true

	default:
		resp.Allowed = true
	}

	return resp, nil
}

func (v *Validator) handleDeletion(oldTemplate *mgmtv3.PodSecurityAdmissionConfigurationTemplate) (clustersUsingTemplate int, clusterType string, err error) {

	// we can't allow templates to be deleted if they are being used by active clusters. Depending on the distro,
	// the template reference could be stored on the v1.Cluster or v3.Cluster.
	mgmtClusters, err := v.ManagementClusterCache.GetByIndex(byPodSecurityAdmissionConfigurationName, oldTemplate.Name)
	if err != nil {
		return 0, "management", fmt.Errorf("error encountered within management cluster indexer: %w", err)
	} else if len(mgmtClusters) > 0 {
		return len(mgmtClusters), "management", nil
	}

	provClusters, err := v.provisioningClusterCache.GetByIndex(byPodSecurityAdmissionConfigurationName, oldTemplate.Name)
	if err != nil {
		return 0, "provisioning", fmt.Errorf("error encountered within provisioning cluster indexer: %w", err)
	} else if len(provClusters) > 0 {
		return len(provClusters), "provisioning", nil
	}

	return 0, "", nil
}

func (v *Validator) validateConfiguration(configurationTemplate *mgmtv3.PodSecurityAdmissionConfigurationTemplate) error {
	defaults := configurationTemplate.Configuration.Defaults

	// validate any provided defaults
	if err := validateLevel(field.NewPath("defaults", "enforce"), defaults.Enforce).ToAggregate(); err != nil {
		return err
	}
	if err := validateVersion(field.NewPath("defaults", "enforce-version"), defaults.EnforceVersion).ToAggregate(); err != nil {
		return err
	}

	if err := validateLevel(field.NewPath("defaults", "warn"), defaults.Warn).ToAggregate(); err != nil {
		return err
	}
	if err := validateVersion(field.NewPath("defaults", "warn-version"), defaults.WarnVersion).ToAggregate(); err != nil {
		return err
	}

	if err := validateLevel(field.NewPath("defaults", "audit"), defaults.Audit).ToAggregate(); err != nil {
		return err
	}
	if err := validateVersion(field.NewPath("defaults", "audit-version"), defaults.AuditVersion).ToAggregate(); err != nil {
		return err
	}

	// validate exemptions
	if err := validateUsernames(configurationTemplate).ToAggregate(); err != nil {
		return err
	}

	if err := validateRuntimeClasses(configurationTemplate).ToAggregate(); err != nil {
		return err
	}

	return validateNamespaces(configurationTemplate).ToAggregate()
}

func validateLevel(p *field.Path, value string) field.ErrorList {
	if value == "" {
		return nil
	}
	errs := field.ErrorList{}
	_, err := api.ParseLevel(value)
	if err != nil {
		errs = append(errs, field.Invalid(p, value, err.Error()))
	}
	return errs
}

func validateVersion(p *field.Path, value string) field.ErrorList {
	if value == "" {
		return nil
	}
	errs := field.ErrorList{}
	_, err := api.ParseVersion(value)
	if err != nil {
		errs = append(errs, field.Invalid(p, value, err.Error()))
	}
	return errs
}

func validateNamespaces(template *mgmtv3.PodSecurityAdmissionConfigurationTemplate) field.ErrorList {
	errs := field.ErrorList{}
	validSet := sets.NewString()
	configuration := template.Configuration
	for i, ns := range configuration.Exemptions.Namespaces {
		err := machinery.ValidateNamespaceName(ns, false)
		if len(err) > 0 {
			path := field.NewPath("exemptions", "namespaces").Index(i)
			errs = append(errs, field.Invalid(path, ns, strings.Join(err, ", ")))
			continue
		}
		if validSet.Has(ns) {
			path := field.NewPath("exemptions", "namespaces").Index(i)
			errs = append(errs, field.Duplicate(path, ns))
			continue
		}
		validSet.Insert(ns)
	}
	return errs
}

func validateRuntimeClasses(template *mgmtv3.PodSecurityAdmissionConfigurationTemplate) field.ErrorList {
	errs := field.ErrorList{}
	validSet := sets.NewString()
	configuration := template.Configuration
	for i, rc := range configuration.Exemptions.RuntimeClasses {
		err := machinery.NameIsDNSSubdomain(rc, false)
		if len(err) > 0 {
			path := field.NewPath("exemptions", "runtimeClasses").Index(i)
			errs = append(errs, field.Invalid(path, rc, strings.Join(err, ", ")))
			continue
		}
		if validSet.Has(rc) {
			path := field.NewPath("exemptions", "runtimeClasses").Index(i)
			errs = append(errs, field.Duplicate(path, rc))
			continue
		}
		validSet.Insert(rc)
	}
	return errs
}

func validateUsernames(template *mgmtv3.PodSecurityAdmissionConfigurationTemplate) field.ErrorList {
	errs := field.ErrorList{}
	validSet := sets.NewString()
	configuration := template.Configuration
	for i, uname := range configuration.Exemptions.Usernames {
		if uname == "" {
			path := field.NewPath("exemptions", "usernames").Index(i)
			errs = append(errs, field.Invalid(path, uname, "username must not be empty"))
			continue
		}
		if validSet.Has(uname) {
			path := field.NewPath("exemptions", "usernames").Index(i)
			errs = append(errs, field.Duplicate(path, uname))
			continue
		}
		validSet.Insert(uname)
	}

	return errs
}
