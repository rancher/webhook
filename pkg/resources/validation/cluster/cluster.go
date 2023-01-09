package cluster

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	"github.com/blang/semver"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	psa "github.com/rancher/webhook/pkg/podsecurityadmission"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/authorization/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

var managementGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "clusters",
}

var parsedRangeLessThan125 = semver.MustParseRange("< 1.25.0-rancher0")
var parsedRangeLessThan123 = semver.MustParseRange("< 1.23.0-rancher0")

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
		cluster, err := objectsv3.ClusterFromRequest(&request.AdmissionRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to get cluster from request: %w", err)
		}
		// no need to validate the local cluster, or imported cluster which represents a KEv2 cluster (GKE/EKS/AKS) or v1 Provisioning Cluster
		if cluster.Name == "local" || cluster.Spec.RancherKubernetesEngineConfig == nil {
			return admission.ResponseAllowed(), nil
		}
		response, err = v.validatePSACT(request)
		if err != nil {
			return nil, fmt.Errorf("failed to validate PodSecurityAdmissionConfigurationTemplate(PSACT): %w", err)
		}
		if !response.Allowed {
			return response, nil
		}
		response, err = v.validatePSP(request)
		if err != nil {
			return nil, fmt.Errorf("failed to validate PSP: %w", err)
		}
		if !response.Allowed {
			return response, nil
		}
	}
	return admission.ResponseAllowed(), nil
}

func toExtra(extra map[string]authenticationv1.ExtraValue) map[string]v1.ExtraValue {
	result := map[string]v1.ExtraValue{}
	for k, v := range extra {
		result[k] = v1.ExtraValue(v)
	}
	return result
}

// validateFleetPermissions validates whether the request maker has required permissions around FleetWorkspace.
func (v *Validator) validateFleetPermissions(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	oldCluster, newCluster, err := objectsv3.ClusterOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get old and new clusters from request: %w", err)
	}

	if newCluster.Spec.FleetWorkspaceName == "" || oldCluster.Spec.FleetWorkspaceName == newCluster.Spec.FleetWorkspaceName {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
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
	return admission.ResponseAllowed(), nil
}

// validatePSACT validates the cluster spec when PodSecurityAdmissionConfigurationTemplate is used.
func (v *Validator) validatePSACT(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	oldCluster, newCluster, err := objectsv3.ClusterOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get old and new clusters from request: %w", err)
	}
	newTemplateName := newCluster.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName
	oldTemplateName := oldCluster.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName
	parsedVersion, err := psa.GetClusterVersion(newCluster.Spec.RancherKubernetesEngineConfig.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cluster version: %w", err)
	}
	if parsedRangeLessThan123(parsedVersion) && newTemplateName != "" {
		return admission.ResponseBadRequest("PodSecurityAdmissionConfigurationTemplate(PSACT) is only supported in k8s version 1.23 and above"), nil
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
			return admission.ResponseAllowed(), nil
		case admissionv1.Update:
			// In the case of unsetting DefaultPodSecurityAdmissionConfigurationTemplateName,
			// validate that the configuration for PodSecurityAdmission under the kube-api.admission_configuration section
			// is different between the new and old clusters.
			// It is possible that user drops DefaultPodSecurityAdmissionConfigurationTemplateName and set the config
			// under kube-api.admission_configuration at the same time.
			if oldTemplateName != "" {
				newConfig, found := psa.GetPluginConfigFromCluster(newCluster)
				if !found {
					// not found means the kube-api.admission_configuration section is also removed, which is good
					return admission.ResponseAllowed(), nil
				}
				oldConfig, _ := psa.GetPluginConfigFromCluster(oldCluster)
				if reflect.DeepEqual(newConfig, oldConfig) {
					return admission.ResponseBadRequest("The Plugin Config for PodSecurity under kube-api.admission_configuration is the same as the previously-set PodSecurityAdmissionConfigurationTemplate." +
						" Please either change the Plugin Config or set the DefaultPodSecurityAdmissionConfigurationTemplateName."), nil
				}
			}
		}
	}
	return admission.ResponseAllowed(), nil
}

// checkPSAConfigOnCluster validates the cluster spec when DefaultPodSecurityAdmissionConfigurationTemplateName is set.
func (v *Validator) checkPSAConfigOnCluster(cluster *apisv3.Cluster) (*admissionv1.AdmissionResponse, error) {
	// validate that extra_args.admission-control-config-file is not set at the same time
	_, found := cluster.Spec.RancherKubernetesEngineConfig.Services.KubeAPI.ExtraArgs["admission-control-config-file"]
	if found {
		return admission.ResponseBadRequest("could not use external admission control configuration file when using PodSecurityAdmissionConfigurationTemplate"), nil
	}
	// validate that the configuration for PodSecurityAdmission under the kube-api.admission_configuration section
	// matches the content of the PodSecurityAdmissionConfigurationTemplate specified in the cluster
	name := cluster.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName
	template, err := v.psact.Get(name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return admission.ResponseBadRequest(err.Error()), nil
		}
		return nil, fmt.Errorf("failed to get PodSecurityAdmissionConfigurationTemplate [%s]: %w", name, err)
	}
	fromTemplate, err := psa.GetPluginConfigFromTemplate(template, cluster.Spec.RancherKubernetesEngineConfig.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to get the PluginConfig: %w", err)
	}
	fromAdmissionConfig, found := psa.GetPluginConfigFromCluster(cluster)
	if !found {
		return admission.ResponseBadRequest("PodSecurity Configuration is not found under kube-api.admission_configuration"), nil
	}
	var psaConfig, psaConfig2 any
	err = json.Unmarshal(fromTemplate.Configuration.Raw, &psaConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal PodSecurityConfiguration from template: %w", err)
	}
	err = json.Unmarshal(fromAdmissionConfig.Configuration.Raw, &psaConfig2)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal PodSecurityConfiguration from admissionConfig: %w", err)
	}
	if !equality.Semantic.DeepEqual(psaConfig, psaConfig2) {
		return admission.ResponseBadRequest("PodSecurity Configuration under kube-api.admission_configuration " +
			"does not match the content of the PodSecurityAdmissionConfigurationTemplate"), nil
	}
	return admission.ResponseAllowed(), nil
}

// validatePSP validates if the PSP feature is enabled in a cluster which version is 1.25 or above.
func (v *Validator) validatePSP(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	cluster, err := objectsv3.ClusterFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster from request: %w", err)
	}
	parsedVersion, err := psa.GetClusterVersion(cluster.Spec.RancherKubernetesEngineConfig.Version)
	if err != nil {
		return nil, fmt.Errorf("failed to parse cluster version: %w", err)
	}
	if parsedRangeLessThan125(parsedVersion) {
		return admission.ResponseAllowed(), nil
	}
	if cluster.Spec.DefaultPodSecurityPolicyTemplateName != "" || cluster.Spec.RancherKubernetesEngineConfig.Services.KubeAPI.PodSecurityPolicy {
		return admission.ResponseBadRequest("cannot enable PodSecurityPolicy(PSP) or use PSP Template in cluster which k8s version is 1.25 and above"), nil
	}

	return admission.ResponseAllowed(), nil
}
