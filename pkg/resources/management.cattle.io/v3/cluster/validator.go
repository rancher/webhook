package cluster

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"

	"github.com/blang/semver"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	psa "github.com/rancher/webhook/pkg/podsecurityadmission"
	"github.com/rancher/webhook/pkg/resources/common"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

const (
	localCluster             = "local"
	VersionManagementAnno    = "rancher.io/imported-cluster-version-management"
	VersionManagementSetting = "imported-cluster-version-management"
)

var parsedRangeLessThan123 = semver.MustParseRange("< 1.23.0-rancher0")

// NewValidator returns a new validator for management clusters.
func NewValidator(
	sar authorizationv1.SubjectAccessReviewInterface,
	cache v3.PodSecurityAdmissionConfigurationTemplateCache,
	userCache v3.UserCache,
	featureCache v3.FeatureCache,
	settingCache v3.SettingCache,
) *Validator {
	return &Validator{
		admitter: admitter{
			sar:          sar,
			psact:        cache,
			userCache:    userCache, // userCache is nil for downstream clusters.
			featureCache: featureCache,
			settingCache: settingCache, // settingCache is nil for downstream clusters
		},
	}
}

// Validator ValidatingWebhook for management clusters.
type Validator struct {
	admitter admitter
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
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	valWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope, v.Operations())
	valWebhook.FailurePolicy = admission.Ptr(admissionregistrationv1.Ignore)
	return []admissionregistrationv1.ValidatingWebhook{*valWebhook}
}

// Admitters returns the admitter objects used to validate clusters.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
	sar          authorizationv1.SubjectAccessReviewInterface
	psact        v3.PodSecurityAdmissionConfigurationTemplateCache
	userCache    v3.UserCache
	featureCache v3.FeatureCache
	settingCache v3.SettingCache
}

// Admit handles the webhook admission request sent to this webhook.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	oldCluster, newCluster, err := objectsv3.ClusterOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed get old and new clusters from request: %w", err)
	}

	if request.Operation == admissionv1.Delete && oldCluster.Name == localCluster {
		// deleting "local" cluster could corrupt the cluster Rancher is deployed in
		return admission.ResponseBadRequest("local cluster may not be deleted"), nil
	}

	response, err := a.validateFleetPermissions(request, oldCluster, newCluster)
	if err != nil {
		return nil, fmt.Errorf("failed to validate fleet permissions: %w", err)
	}
	if !response.Allowed {
		return response, nil
	}

	if a.userCache != nil {
		// The following checks don't make sense for downstream clusters (userCache == nil)
		if request.Operation == admissionv1.Create {
			if fieldErr := common.CheckCreatorIDAndNoCreatorRBAC(newCluster); fieldErr != nil {
				return admission.ResponseBadRequest(fieldErr.Error()), nil
			}
			fieldErr, err := common.CheckCreatorPrincipalName(a.userCache, newCluster)
			if err != nil {
				return nil, fmt.Errorf("error checking creator principal: %w", err)
			}
			if fieldErr != nil {
				return admission.ResponseBadRequest(fieldErr.Error()), nil
			}
		} else if request.Operation == admissionv1.Update {
			if fieldErr := common.CheckCreatorAnnotationsOnUpdate(oldCluster, newCluster); fieldErr != nil {
				return admission.ResponseBadRequest(fieldErr.Error()), nil
			}
		}
	}

	if response, err = a.validatePodDisruptionBudget(oldCluster, newCluster, request.Operation); err != nil || !response.Allowed {
		return response, err
	}

	if response, err = a.validatePriorityClass(oldCluster, newCluster, request.Operation); err != nil || !response.Allowed {
		return response, err
	}

	response, err = a.validatePSACT(oldCluster, newCluster, request.Operation)
	if err != nil {
		return nil, fmt.Errorf("failed to validate PodSecurityAdmissionConfigurationTemplate(PSACT): %w", err)
	}
	if !response.Allowed {
		return response, nil
	}

	if a.settingCache != nil {
		// The following checks don't make sense for downstream clusters (settingCache == nil)
		response, err = a.validateVersionManagementFeature(oldCluster, newCluster, request.Operation)
		if err != nil {
			return nil, fmt.Errorf("failed to validate version management feature: %w", err)
		}
		if !response.Allowed {
			return response, nil
		}
	}

	return response, nil
}

func toExtra(extra map[string]authenticationv1.ExtraValue) map[string]v1.ExtraValue {
	result := map[string]v1.ExtraValue{}
	for k, v := range extra {
		result[k] = v1.ExtraValue(v)
	}
	return result
}

// validateFleetPermissions validates whether the request maker has required permissions around FleetWorkspace.
func (a *admitter) validateFleetPermissions(request *admission.Request, oldCluster, newCluster *apisv3.Cluster) (*admissionv1.AdmissionResponse, error) {
	// Ensure that the FleetWorkspaceName field cannot be unset once it is set, as it would cause (likely unintentional)
	// cluster deletion. Note that we're only enforcing this rule on UPDATE because Spec.FleetWorkspaceName will be
	// empty on cluster deletion, which is fine.
	fleetWorkspaceUnset := newCluster.Spec.FleetWorkspaceName == "" && oldCluster.Spec.FleetWorkspaceName != ""
	if request.Operation == admissionv1.Update && fleetWorkspaceUnset {
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Status:  "Failure",
				Message: "once set, field FleetWorkspaceName cannot be made empty",
				Reason:  metav1.StatusReasonInvalid,
				Code:    http.StatusBadRequest,
			},
			Allowed: false,
		}, nil
	}

	// If the FleetWorkspaceName is empty or unchanged, there's no need to make a SAR request.
	if newCluster.Spec.FleetWorkspaceName == "" || oldCluster.Spec.FleetWorkspaceName == newCluster.Spec.FleetWorkspaceName {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}

	resp, err := a.sar.Create(request.Context, &v1.SubjectAccessReview{
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
func (a *admitter) validatePSACT(oldCluster, newCluster *apisv3.Cluster, op admissionv1.Operation) (*admissionv1.AdmissionResponse, error) {
	if op != admissionv1.Create && op != admissionv1.Update {
		return admission.ResponseAllowed(), nil
	}
	// no need to validate the PodSecurityAdmissionConfigurationTemplate on a local cluster,
	// or imported cluster which represents a KEv2 cluster (GKE/EKS/AKS) or v1 Provisioning Cluster
	if newCluster.Name == localCluster || newCluster.Spec.RancherKubernetesEngineConfig == nil {
		return admission.ResponseAllowed(), nil
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
		response, err := a.checkPSAConfigOnCluster(newCluster)
		if err != nil {
			return nil, fmt.Errorf("failed to check the PodSecurity Config in the cluster %s: %w", newCluster.Name, err)
		}
		if !response.Allowed {
			return response, nil
		}
	} else {
		switch op {
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

// validatePriorityClass validates that the Priority Class defined in the cluster SchedulingCustomization field is properly
// configured. The cluster-agent-scheduling-customization feature must be enabled to configure a Priority Class, however an existing
// Priority Class may be deleted even if the feature is disabled.
func (a *admitter) validatePriorityClass(oldCluster, newCluster *apisv3.Cluster, op admissionv1.Operation) (*admissionv1.AdmissionResponse, error) {
	if op != admissionv1.Create && op != admissionv1.Update {
		return admission.ResponseAllowed(), nil
	}

	newClusterScheduling := getSchedulingCustomization(newCluster)
	oldClusterScheduling := getSchedulingCustomization(oldCluster)

	var newPC, oldPC *apisv3.PriorityClassSpec
	if newClusterScheduling != nil {
		newPC = newClusterScheduling.PriorityClass
	}

	if oldClusterScheduling != nil {
		oldPC = oldClusterScheduling.PriorityClass
	}

	if newPC == nil {
		return admission.ResponseAllowed(), nil
	}

	featuredEnabled, err := a.featureCache.Get(common.SchedulingCustomizationFeatureName)
	if err != nil {
		return nil, fmt.Errorf("failed to determine status of '%s' feature", common.SchedulingCustomizationFeatureName)
	}

	enabled := featuredEnabled.Status.Default
	if featuredEnabled.Spec.Value != nil {
		enabled = *featuredEnabled.Spec.Value
	}

	// if the feature is disabled then we should not permit any changes between the old and new clusters other than deletion
	if !enabled && oldPC != nil {
		if reflect.DeepEqual(*oldPC, *newPC) {
			return admission.ResponseAllowed(), nil
		}

		return admission.ResponseBadRequest(fmt.Sprintf("'%s' feature is disabled, will only permit removal of Scheduling Customization fields until reenabled", common.SchedulingCustomizationFeatureName)), nil
	}

	if !enabled && oldPC == nil {
		return admission.ResponseBadRequest(fmt.Sprintf("the '%s' feature must be enabled in order to configure a Priority Class or Pod Disruption Budget", common.SchedulingCustomizationFeatureName)), nil
	}

	if newPC.PreemptionPolicy != nil && *newPC.PreemptionPolicy != corev1.PreemptNever && *newPC.PreemptionPolicy != corev1.PreemptLowerPriority && *newPC.PreemptionPolicy != "" {
		return admission.ResponseBadRequest("Priority Class Preemption value must be 'Never', 'PreemptLowerPriority', or empty"), nil
	}

	if newPC.Value > 1000000000 {
		return admission.ResponseBadRequest("Priority Class value cannot be greater than 1 billion"), nil
	}

	if newPC.Value < -1000000000 {
		return admission.ResponseBadRequest("Priority Class value cannot be less than negative 1 billion"), nil
	}

	return admission.ResponseAllowed(), nil
}

// validatePodDisruptionBudget validates that the Pod Disruption Budget defined in the cluster SchedulingCustomization field is properly
// configured. The cluster-agent-scheduling-customization feature must be enabled to configure a Pod Disruption Budget, however an existing
// Pod Disruption Budget may be deleted even if the feature is disabled.
func (a *admitter) validatePodDisruptionBudget(oldCluster, newCluster *apisv3.Cluster, op admissionv1.Operation) (*admissionv1.AdmissionResponse, error) {
	if op != admissionv1.Create && op != admissionv1.Update {
		return admission.ResponseAllowed(), nil
	}
	newClusterScheduling := getSchedulingCustomization(newCluster)
	oldClusterScheduling := getSchedulingCustomization(oldCluster)

	var newPDB, oldPDB *apisv3.PodDisruptionBudgetSpec
	if newClusterScheduling != nil {
		newPDB = newClusterScheduling.PodDisruptionBudget
	}

	if oldClusterScheduling != nil {
		oldPDB = oldClusterScheduling.PodDisruptionBudget
	}

	if newPDB == nil {
		return admission.ResponseAllowed(), nil
	}

	featuredEnabled, err := a.featureCache.Get(common.SchedulingCustomizationFeatureName)
	if err != nil {
		return nil, fmt.Errorf("failed to determine status of '%s' feature", common.SchedulingCustomizationFeatureName)
	}

	enabled := featuredEnabled.Status.Default
	if featuredEnabled.Spec.Value != nil {
		enabled = *featuredEnabled.Spec.Value
	}

	// if the feature is disabled then we should not permit any changes between the old and new clusters other than deletion
	if !enabled && oldPDB != nil {
		if reflect.DeepEqual(*oldPDB, *newPDB) {
			return admission.ResponseAllowed(), nil
		}

		return admission.ResponseBadRequest(fmt.Sprintf("'%s' feature is disabled, will only permit removal of Scheduling Customization fields until reenabled", common.SchedulingCustomizationFeatureName)), nil
	}

	if !enabled && oldPDB == nil {
		return admission.ResponseBadRequest(fmt.Sprintf("the '%s' feature must be enabled in order to configure a Priority Class or Pod Disruption Budget", common.SchedulingCustomizationFeatureName)), nil
	}

	minAvailStr := newPDB.MinAvailable
	maxUnavailStr := newPDB.MaxUnavailable

	if (minAvailStr == "" && maxUnavailStr == "") ||
		(minAvailStr == "0" && maxUnavailStr == "0") ||
		(minAvailStr != "" && minAvailStr != "0") && (maxUnavailStr != "" && maxUnavailStr != "0") {
		return admission.ResponseBadRequest("both minAvailable and maxUnavailable cannot be set to a non zero value, at least one must be omitted or set to zero"), nil
	}

	minAvailIsString := false
	maxUnavailIsString := false

	minAvailInt, err := strconv.Atoi(minAvailStr)
	if err != nil {
		minAvailIsString = minAvailStr != ""
	}

	maxUnavailInt, err := strconv.Atoi(maxUnavailStr)
	if err != nil {
		maxUnavailIsString = maxUnavailStr != ""
	}

	if !minAvailIsString && minAvailInt < 0 {
		return admission.ResponseBadRequest("minAvailable cannot be set to a negative integer"), nil
	}

	if !maxUnavailIsString && maxUnavailInt < 0 {
		return admission.ResponseBadRequest("maxUnavailable cannot be set to a negative integer"), nil
	}

	if minAvailIsString && !common.PdbPercentageRegex.Match([]byte(minAvailStr)) {
		return admission.ResponseBadRequest(fmt.Sprintf("minAvailable must be a non-negative whole integer or a percentage value between 0 and 100, regex used is '%s'", common.PdbPercentageRegex.String())), nil
	}

	if maxUnavailIsString && maxUnavailStr != "" && !common.PdbPercentageRegex.Match([]byte(maxUnavailStr)) {
		return admission.ResponseBadRequest(fmt.Sprintf("minAvailable must be a non-negative whole integer or a percentage value between 0 and 100, regex used is '%s'", common.PdbPercentageRegex.String())), nil
	}

	return admission.ResponseAllowed(), nil
}

// checkPSAConfigOnCluster validates the cluster spec when DefaultPodSecurityAdmissionConfigurationTemplateName is set.
func (a *admitter) checkPSAConfigOnCluster(cluster *apisv3.Cluster) (*admissionv1.AdmissionResponse, error) {
	// validate that extra_args.admission-control-config-file is not set at the same time
	_, found := cluster.Spec.RancherKubernetesEngineConfig.Services.KubeAPI.ExtraArgs["admission-control-config-file"]
	if found {
		return admission.ResponseBadRequest("could not use external admission control configuration file when using PodSecurityAdmissionConfigurationTemplate"), nil
	}
	// validate that the configuration for PodSecurityAdmission under the kube-api.admission_configuration section
	// matches the content of the PodSecurityAdmissionConfigurationTemplate specified in the cluster
	name := cluster.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName
	template, err := a.psact.Get(name)
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

func getSchedulingCustomization(cluster *apisv3.Cluster) *apisv3.AgentSchedulingCustomization {
	if cluster == nil {
		return nil
	}

	if cluster.Spec.ClusterAgentDeploymentCustomization == nil {
		return nil
	}

	if cluster.Spec.ClusterAgentDeploymentCustomization.SchedulingCustomization == nil {
		return nil
	}

	return cluster.Spec.ClusterAgentDeploymentCustomization.SchedulingCustomization
}

// validateVersionManagementFeature validates the annotation for the version management feature is set with valid value on the imported RKE2/K3s cluster,
// additionally, it permits to the response if either of the following is true:
//   - the annotation is found on a cluster rather than imported RKE2/K3s cluster;
//   - the spec.rke2Config or spec.k3sConfig is changed when the version management feature is disabled for the cluster (emits a warning);
//
// however, this annotation does not take any effect on clusters that are not imported RKE2/K3s clusters.
func (a *admitter) validateVersionManagementFeature(oldCluster, newCluster *apisv3.Cluster, op admissionv1.Operation) (*admissionv1.AdmissionResponse, error) {
	if op != admissionv1.Create && op != admissionv1.Update {
		return admission.ResponseAllowed(), nil
	}

	driver := newCluster.Status.Driver

	if driver != apisv3.ClusterDriverRke2 && driver != apisv3.ClusterDriverK3s {
		response := admission.ResponseAllowed()
		return response, nil
	}

	// reaching this point indicates the cluster is an imported RKE2/K3s cluster
	val, exist := newCluster.Annotations[VersionManagementAnno]
	if !exist {
		message := fmt.Sprintf("the %s annotation is missing", VersionManagementAnno)
		return admission.ResponseBadRequest(message), nil
	}
	if val != "true" && val != "false" && val != "system-default" {
		message := fmt.Sprintf("the value of the %s annotation must be one of the following: true, false, system-default", VersionManagementAnno)
		return admission.ResponseBadRequest(message), nil
	}
	enabled, err := a.versionManagementEnabled(newCluster)
	if err != nil {
		return nil, fmt.Errorf("failed to check the version management feature: %w", err)
	}
	response := admission.ResponseAllowed()
	if !enabled && op == admissionv1.Update {
		if driver == apisv3.ClusterDriverRke2 {
			if !reflect.DeepEqual(oldCluster.Spec.Rke2Config, newCluster.Spec.Rke2Config) && newCluster.Spec.Rke2Config != nil {
				msg := fmt.Sprintf("Cluster [%s]: changes to the Rke2Config field will take effect after the version management is enabled on the cluster", newCluster.Name)
				response.Warnings = append(response.Warnings, msg)
			}
		}
		if driver == apisv3.ClusterDriverK3s {
			if !reflect.DeepEqual(oldCluster.Spec.K3sConfig, newCluster.Spec.K3sConfig) && newCluster.Spec.K3sConfig != nil {
				msg := fmt.Sprintf("Cluster [%s]: changes to the K3sConfig field will take effect after the version management is enabled on the cluster", newCluster.Name)
				response.Warnings = append(response.Warnings, msg)
			}
		}
	}
	return response, nil
}

func (a *admitter) versionManagementEnabled(cluster *apisv3.Cluster) (bool, error) {
	if cluster == nil {
		return false, fmt.Errorf("cluster is nil")
	}
	val, ok := cluster.Annotations[VersionManagementAnno]
	if !ok {
		return false, fmt.Errorf("the %s annotation is missing from the cluster", VersionManagementAnno)
	}
	if val == "true" {
		return true, nil
	}
	if val == "false" {
		return false, nil
	}
	if val == "system-default" {
		s, err := a.settingCache.Get(VersionManagementSetting)
		if err != nil {
			return false, err
		}
		actual := s.Value
		if actual == "" {
			actual = s.Default
		}
		if actual == "true" {
			return true, nil
		}
		if actual == "false" {
			return false, nil
		}
		return false, fmt.Errorf("the value (%s) of the %s setting is invalid", actual, VersionManagementSetting)
	}
	return false, fmt.Errorf("the value of the %s annotation is invalid", VersionManagementAnno)
}
