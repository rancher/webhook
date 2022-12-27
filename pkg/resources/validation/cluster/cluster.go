package cluster

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/blang/semver"

	psav1 "k8s.io/pod-security-admission/admission/api/v1"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	psa "github.com/rancher/webhook/pkg/podsecurityadmission"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

var managementGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "clusters",
}

var parsedRangeAtLeast125 = semver.MustParseRange(">= 1.25.0-rancher0")

// NewValidator returns a new validator for management clusters.
func NewValidator(sar authorizationv1.SubjectAccessReviewInterface, cache v3.PodSecurityAdmissionConfigurationTemplateCache) *Validator {
	return &Validator{
		sar:   sar,
		psact: cache,
	}
}

// Validator ValidatingWebhook for management clusters.
type Validator struct {
	sar   authorizationv1.SubjectAccessReviewInterface
	psact v3.PodSecurityAdmissionConfigurationTemplateCache
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return managementGVR
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update, admissionregistrationv1.Delete}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) *admissionregistrationv1.ValidatingWebhook {
	valWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope)
	valWebhook.FailurePolicy = admission.Ptr(admissionregistrationv1.Ignore)
	return valWebhook
}

// Admit handles the webhook admission request sent to this webhook.
func (v *Validator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	response, err := v.validateFleetPermissions(request)
	if err != nil {
		return nil, fmt.Errorf("failed to validate fleet permissions: %w", err)
	}
	if !response.Allowed {
		return response, nil
	}

	if request.Operation == admissionv1.Create || request.Operation == admissionv1.Update {
		response, err = v.validatePSACT(request)
		if err != nil {
			return nil, fmt.Errorf("failed to validate PodSecurityAdmissionConfigurationTemplate: %w", err)
		}
		if !response.Allowed {
			return response, nil
		}
	}
	return psa.AdmissionResponseAllowed(), nil
}

func toExtra(extra map[string]authenticationv1.ExtraValue) map[string]v1.ExtraValue {
	result := map[string]v1.ExtraValue{}
	for k, v := range extra {
		result[k] = v1.ExtraValue(v)
	}
	return result
}

// validateFleetPermissions validates whether the request maker has required permissions around FleetWorkspace
func (v *Validator) validateFleetPermissions(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	oldCluster, newCluster, err := objectsv3.ClusterOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get old and new clusters from request: %w", err)
	}

	if newCluster.Spec.FleetWorkspaceName == "" || oldCluster.Spec.FleetWorkspaceName == newCluster.Spec.FleetWorkspaceName {
		return psa.AdmissionResponseAllowed(), nil
	}

	resp, err := v.sar.Create(request.Context, &v1.SubjectAccessReview{
		Spec: v1.SubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Verb:     "fleetaddcluster",
				Version:  "v3",
				Resource: "fleetworkspaces",
				Group:    "management.cattle.io",
				Name:     newCluster.Spec.FleetWorkspaceName,
			},
			User:   request.UserInfo.Username,
			Groups: request.UserInfo.Groups,
			Extra:  toExtra(request.UserInfo.Extra),
			UID:    request.UserInfo.UID,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to check SubjectAccessReview for cluster [%s]: %w", newCluster.Name, err)
	}

	if !resp.Status.Allowed {
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Status:  "Failure",
				Message: resp.Status.Reason,
				Reason:  metav1.StatusReasonUnauthorized,
				Code:    http.StatusUnauthorized,
			},
			Allowed: false,
		}, nil
	}
	return psa.AdmissionResponseAllowed(), nil
}

// validatePSACT validates the cluster spec when PodSecurityAdmissionConfigurationTemplate is used
func (v *Validator) validatePSACT(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	oldCluster, newCluster, err := objectsv3.ClusterOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get old and new clusters from request: %w", err)
	}
	if newCluster.Name == "local" {
		return psa.AdmissionResponseAllowed(), nil
	}
	if newCluster.Spec.RancherKubernetesEngineConfig == nil {
		return psa.AdmissionResponseBadRequest("rancher_kubernetes_engine_config can not be nil"), nil
	}
	newTemplateName := newCluster.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName
	oldTemplateName := oldCluster.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName
	parsedVersion, err := getClusterVersion(newCluster.Spec.RancherKubernetesEngineConfig.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cluster version: %w", err)
	}
	if !parsedRangeAtLeast125(parsedVersion) && newTemplateName != "" {
		msg := "PodSecurityAdmissionConfigurationTemplate is only supported in Kubernetes version 1.25 and above"
		return psa.AdmissionResponseBadRequest(msg), nil
	}
	if newTemplateName != "" {
		response, err := v.checkPSAConfigOnCluster(newCluster)
		if err != nil {
			return nil, fmt.Errorf("failed to check the PodSecurity Config in the cluster %s: %w", newCluster.Name, err)
		}
		if !response.Allowed {
			return response, nil
		}
	} else {
		switch request.Operation {
		case admissionv1.Create:
			return psa.AdmissionResponseAllowed(), nil
		case admissionv1.Update:
			// In the case of unsetting DefaultPodSecurityAdmissionConfigurationTemplateName,
			// validate that the configuration for PodSecurityAdmission under the kube-api.admission_configuration section
			// is different between the new and old clusters.
			// It is possible that user drops DefaultPodSecurityAdmissionConfigurationTemplateName and set the config
			// under kube-api.admission_configuration at the same time.
			if oldTemplateName != "" {
				newConfig, found := psa.GetPlugConfigFromCluster(newCluster)
				if !found {
					// not found means the kube-api.admission_configuration section is also removed, which is good
					return psa.AdmissionResponseAllowed(), nil
				}
				oldConfig, _ := psa.GetPlugConfigFromCluster(oldCluster)
				if reflect.DeepEqual(newConfig, oldConfig) {
					msg := "The Plugin Config for PodSecurity under kube-api.admission_configuration is the same as the previously-set PodSecurityAdmissionConfigurationTemplate." +
						" Please either change the Plugin Config or set the DefaultPodSecurityAdmissionConfigurationTemplateName."
					return psa.AdmissionResponseBadRequest(msg), nil
				}
			}
		}
	}
	return psa.AdmissionResponseAllowed(), nil
}

// checkPSAConfigOnCluster validates the cluster spec when DefaultPodSecurityAdmissionConfigurationTemplateName is set
func (v *Validator) checkPSAConfigOnCluster(cluster *apisv3.Cluster) (*admissionv1.AdmissionResponse, error) {
	// validate that extra_args.admission-control-config-file is not set at the same time
	_, found := cluster.Spec.RancherKubernetesEngineConfig.Services.KubeAPI.ExtraArgs["admission-control-config-file"]
	if found {
		msg := "could not use external admission control configuration file when using PodSecurityAdmissionConfigurationTemplate"
		return psa.AdmissionResponseBadRequest(msg), nil
	}
	// validate that the configuration for PodSecurityAdmission under the kube-api.admission_configuration section
	// matches the content of the PodSecurityAdmissionConfigurationTemplate specified in the cluster
	name := cluster.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName
	template, err := v.psact.Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return psa.AdmissionResponseBadRequest(err.Error()), nil
		}
		return nil, fmt.Errorf("failed to get PodSecurityAdmissionConfigurationTemplate [%s]: %w", name, err)
	}
	fromTemplate, err := psa.GetPluginConfigFromTemplate(template)
	if err != nil {
		return nil, fmt.Errorf("failed to get the PluginConfig: %w", err)
	}
	fromAdmissionConfig, found := psa.GetPlugConfigFromCluster(cluster)
	if !found {
		msg := "PodSecurity Configuration is not found under kube-api.admission_configuration"
		return psa.AdmissionResponseBadRequest(msg), nil
	}
	psaConfig := &psav1.PodSecurityConfiguration{}
	err = json.Unmarshal(fromTemplate.Configuration.Raw, psaConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal PodSecurityConfiguration: %w", err)
	}

	psaConfig2 := &psav1.PodSecurityConfiguration{}
	err = json.Unmarshal(fromAdmissionConfig.Configuration.Raw, psaConfig2)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal PodSecurityConfiguration: %w", err)
	}
	if !reflect.DeepEqual(psaConfig, psaConfig2) {
		msg := "PodSecurity Configuration under kube-api.admission_configuration does not match " +
			"the content of the PodSecurityAdmissionConfigurationTemplate"
		return psa.AdmissionResponseBadRequest(msg), nil
	}
	return psa.AdmissionResponseAllowed(), nil
}

func getClusterVersion(version string) (semver.Version, error) {
	var parsedVersion semver.Version
	if len(version) <= 1 || !strings.HasPrefix(version, "v") {
		return parsedVersion, fmt.Errorf("%s is not valid version", version)
	}
	parsedVersion, err := semver.Parse(version[1:])
	if err != nil {
		return parsedVersion, fmt.Errorf("%s is not valid semver", version)
	}
	return parsedVersion, nil
}
