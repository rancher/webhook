package cluster

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/clients"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/provisioning.cattle.io/v1"
	psa "github.com/rancher/webhook/pkg/podsecurityadmission"
	"github.com/rancher/webhook/pkg/resources/common"
	corev1controller "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	"github.com/rancher/wrangler/v3/pkg/kv"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authv1 "k8s.io/api/authorization/v1"
	k8sv1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/validation"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/trace"
)

const (
	globalNamespace         = "cattle-global-data"
	systemAgentVarDirEnvVar = "CATTLE_AGENT_VAR_DIR"
	failureStatus           = "Failure"
)

var (
	mgmtNameRegex  = regexp.MustCompile("^c-[a-z0-9]{5}$")
	fleetNameRegex = regexp.MustCompile("^[^-][-a-z0-9]+$")
)

// NewProvisioningClusterValidator returns a new validator for provisioning clusters
func NewProvisioningClusterValidator(client *clients.Clients) *ProvisioningClusterValidator {
	return &ProvisioningClusterValidator{
		admitter: provisioningAdmitter{
			sar:               client.K8s.AuthorizationV1().SubjectAccessReviews(),
			mgmtClusterClient: client.Management.Cluster(),
			secretCache:       client.Core.Secret().Cache(),
			psactCache:        client.Management.PodSecurityAdmissionConfigurationTemplate().Cache(),
		},
	}
}

type ProvisioningClusterValidator struct {
	admitter provisioningAdmitter
}

// GVR returns the GroupVersionKind for this CRD.
func (p *ProvisioningClusterValidator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (p *ProvisioningClusterValidator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Update, admissionregistrationv1.Create, admissionregistrationv1.Delete}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (p *ProvisioningClusterValidator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{*admission.NewDefaultValidatingWebhook(p, clientConfig, admissionregistrationv1.NamespacedScope, p.Operations())}
}

// Admitters returns the admitter objects used to validate provisioning clusters.
func (p *ProvisioningClusterValidator) Admitters() []admission.Admitter {
	return []admission.Admitter{&p.admitter}
}

type provisioningAdmitter struct {
	sar               authorizationv1.SubjectAccessReviewInterface
	mgmtClusterClient v3.ClusterClient
	secretCache       corev1controller.SecretCache
	psactCache        v3.PodSecurityAdmissionConfigurationTemplateCache
}

// Admit handles the webhook admission request sent to this webhook.
func (p *provisioningAdmitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("provisioningClusterValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldCluster, cluster, err := objectsv1.ClusterOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}

	response := &admissionv1.AdmissionResponse{}
	if request.Operation == admissionv1.Create || request.Operation == admissionv1.Update {
		if err := p.validateClusterName(request, response, cluster); err != nil || response.Result != nil {
			return response, err
		}

		if err := p.validateMachinePoolNames(request, response, cluster); err != nil || response.Result != nil {
			return response, err
		}

		if response.Result = common.CheckCreatorID(request, oldCluster, cluster); response.Result != nil {
			return response, nil
		}

		if response.Result = validateACEConfig(cluster); response.Result != nil {
			return response, nil
		}

		if response.Result = errorListToStatus(validateAgentDeploymentCustomization(cluster.Spec.ClusterAgentDeploymentCustomization,
			field.NewPath("spec", "clusterAgentDeploymentCustomization"))); response.Result != nil {
			return response, nil
		}

		if response.Result = errorListToStatus(validateAgentDeploymentCustomization(cluster.Spec.FleetAgentDeploymentCustomization,
			field.NewPath("spec", "fleetAgentDeploymentCustomization"))); response.Result != nil {
			return response, nil
		}

		if err := p.validateCloudCredentialAccess(request, response, oldCluster, cluster); err != nil || response.Result != nil {
			return response, err
		}

		if response = p.validateDataDirectories(request, oldCluster, cluster); !response.Allowed {
			return response, err
		}
	}

	if err := p.validatePSACT(request, response, cluster); err != nil || response.Result != nil {
		return response, err
	}

	response.Allowed = true
	return response, nil
}

func getEnvVar(name string, envVars []rkev1.EnvVar) *rkev1.EnvVar {
	var envVar *rkev1.EnvVar
	for _, e := range envVars {
		if e.Name == name {
			envVar = &e
		}
	}
	return envVar
}

// validateSystemAgentDataDirectory validates the effective system agent data directory, ensuring that the intended
// previously configured "CATTLE_AGENT_VAR_DIR" is used during and post migration to the SystemAgent data directory
// field. Once this migration is performed and the field is set, the existing of the env var is completely disallowed.
func (p *provisioningAdmitter) validateSystemAgentDataDirectory(oldCluster, newCluster *v1.Cluster) *admissionv1.AdmissionResponse {
	oldSystemAgentVarDirEnvVar := getEnvVar(systemAgentVarDirEnvVar, oldCluster.Spec.AgentEnvVars)
	newSystemAgentVarDirEnvVar := getEnvVar(systemAgentVarDirEnvVar, newCluster.Spec.AgentEnvVars)
	if oldSystemAgentVarDirEnvVar != nil && oldSystemAgentVarDirEnvVar.Value != "" {
		if newCluster.Spec.RKEConfig.DataDirectories.SystemAgent != "" {
			// new envs vars must be empty and new and old must be equal in order to perform migration
			if newSystemAgentVarDirEnvVar != nil {
				return admission.ResponseBadRequest(fmt.Sprintf(`"%s" env var in "cluster.Spec.AgentEnvVars" must be removed when migrating SystemAgent data directory"`, systemAgentVarDirEnvVar))
			}
			if newCluster.Spec.RKEConfig.DataDirectories.SystemAgent != oldSystemAgentVarDirEnvVar.Value {
				return admission.ResponseBadRequest(fmt.Sprintf(`System Agent data directory must be identical to previous "%s" env var in "cluster.Spec.AgentEnvVars" during migration`, systemAgentVarDirEnvVar))
			}
			// env var was removed or changed
		} else if newSystemAgentVarDirEnvVar == nil || newSystemAgentVarDirEnvVar.Value != oldSystemAgentVarDirEnvVar.Value {
			return admission.ResponseBadRequest(fmt.Sprintf(`"%s" env var in "cluster.Spec.AgentEnvVars" cannot be changed after cluster creation"`, systemAgentVarDirEnvVar))
		}
	} else {
		// post migration
		if newCluster.Spec.RKEConfig.DataDirectories.SystemAgent != oldCluster.Spec.RKEConfig.DataDirectories.SystemAgent {
			return admission.ResponseBadRequest("System Agent data directory cannot be changed after cluster creation")
		}
		if newSystemAgentVarDirEnvVar != nil && newSystemAgentVarDirEnvVar.Value != "" {
			return admission.ResponseBadRequest(fmt.Sprintf(`"%s" env var in "cluster.Spec.AgentEnvVars" cannot be set after cluster creation"`, systemAgentVarDirEnvVar))
		}
	}

	return admission.ResponseAllowed()
}

// validateDataDirectories will ensure that data directories are properly formatted on creation, not duplicated or embed
// each other, and will also validate updates to the cluster object to ensure the data directories are not changed.
// The only exception when a data directory is allowed to be changed is if cluster.Spec.AgentEnvVars has an env var with
// a name of "CATTLE_AGENT_VAR_DIR", which Rancher will perform a one-time migration to set the
// cluster.Spec.RKEConfig.DataDirectories.SystemAgent field for the cluster. validateAgentEnvVars will ensure
// "CATTLE_AGENT_VAR_DIR" is not added, so this exception only applies to the one-time Rancher migration.
func (p *provisioningAdmitter) validateDataDirectories(request *admission.Request, oldCluster, newCluster *v1.Cluster) *admissionv1.AdmissionResponse {
	if newCluster.Spec.RKEConfig == nil {
		return admission.ResponseAllowed()
	}
	distro := newCluster.Spec.RKEConfig.DataDirectories.K8sDistro
	provisioning := newCluster.Spec.RKEConfig.DataDirectories.Provisioning
	systemAgent := newCluster.Spec.RKEConfig.DataDirectories.SystemAgent
	// cannot set "CATTLE_AGENT_VAR_DIR" on create anymore, but still valid as a field until cluster is migrated.
	if request.Operation == admissionv1.Create {
		if slices.ContainsFunc(newCluster.Spec.AgentEnvVars, func(envVar rkev1.EnvVar) bool {
			return envVar.Name == systemAgentVarDirEnvVar
		}) {
			return admission.ResponseBadRequest(
				fmt.Sprintf(`"%s" cannot be set within "cluster.Spec.RKEConfig.AgentEnvVars": use "cluster.Spec.RKEConfig.DataDirectories.SystemAgent"`, systemAgentVarDirEnvVar))
		}
		dataDirectories := map[string]string{
			"Distro":       distro,
			"Provisioning": provisioning,
			"System Agent": systemAgent,
		}
		for name, dir := range dataDirectories {
			response := validateDataDirectoryFormat(dir, name)
			if !response.Allowed {
				return response
			}
		}
		response := validateDataDirectoryHierarchy(dataDirectories)
		if !response.Allowed {
			return response
		}
		return admission.ResponseAllowed()
	}
	if request.Operation != admissionv1.Update {
		return admission.ResponseAllowed()
	}

	if response := p.validateSystemAgentDataDirectory(oldCluster, newCluster); !response.Allowed {
		return response
	}
	if oldCluster.Spec.RKEConfig.DataDirectories.K8sDistro != distro {
		return admission.ResponseBadRequest("Distro data directory cannot be changed after cluster creation")
	}
	if oldCluster.Spec.RKEConfig.DataDirectories.Provisioning != provisioning {
		return admission.ResponseBadRequest("Provisioning data directory cannot be changed after cluster creation")
	}

	return admission.ResponseAllowed()
}

// validateDataDirectoryFormat ensures that no data directory contains a relative path, environment variables,
// shell expressions, or references to the current or parent directory via use of "./" and "../" respectively.
// dir is the path of the data directory, and name corresponds to a print friendly name for this data directory.
func validateDataDirectoryFormat(dir, name string) *admissionv1.AdmissionResponse {
	if dir == "" {
		return admission.ResponseAllowed()
	}
	if !filepath.IsAbs(dir) {
		return admission.ResponseBadRequest(
			fmt.Sprintf("%s data directory must be an absolute path", name))
	}
	if strings.ContainsAny(dir, "\"'`*?#~=%$|&;<>{}[]()") {
		return admission.ResponseBadRequest(
			fmt.Sprintf("%s data directory cannot contain shell expressions", name))
	}
	if filepath.Clean(dir) != dir {
		return admission.ResponseBadRequest(
			fmt.Sprintf("%s data directory is not clean", name))
	}

	return admission.ResponseAllowed()
}

// validateDataDirectoryHierarchy ensures that no directories are equal, and no directories include other directories.
// dataDirs is a map with keys corresponding to print friendly names for these data directories, and values representing
// the specific data directories.
func validateDataDirectoryHierarchy(dataDirs map[string]string) *admissionv1.AdmissionResponse {
	paths := make([]struct {
		name string
		path string
	}, 0, len(dataDirs))
	for name, dir := range dataDirs {
		// do not attempt to validate empty directory
		if dir == "" {
			continue
		}
		paths = append(paths, struct {
			name string
			path string
		}{
			name: name,
			path: dir,
		})
	}

	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			path1 := paths[i]
			path2 := paths[j]

			if path1.path == path2.path {
				return admission.ResponseBadRequest(
					fmt.Sprintf("%s data directory cannot be equal to %s data directory", path1.name, path2.name))
			}

			// check if paths contain one another
			if matched, err := filepath.Match(fmt.Sprintf("%s%c*", path1.path, filepath.Separator), path2.path); err != nil {
				return admission.ResponseBadRequest(
					fmt.Sprintf("error determining if %s data directory is nested inside %s data directory: %s", path2.name, path1.name, err.Error()))
			} else if matched {
				return admission.ResponseBadRequest(
					fmt.Sprintf("%s data directory cannot be nested inside %s data directory", path2.name, path1.name))
			}
			if matched, err := filepath.Match(fmt.Sprintf("%s%c*", path2.path, filepath.Separator), path1.path); err != nil {
				return admission.ResponseBadRequest(
					fmt.Sprintf("error determining if %s data directory is nested inside %s data directory: %s", path1.name, path2.name, err.Error()))
			} else if matched {
				return admission.ResponseBadRequest(
					fmt.Sprintf("%s data directory cannot be nested inside %s data directory", path1.name, path2.name))
			}
		}
	}

	return admission.ResponseAllowed()
}

func (p *provisioningAdmitter) validateCloudCredentialAccess(request *admission.Request, response *admissionv1.AdmissionResponse, oldCluster, newCluster *v1.Cluster) error {
	if newCluster.Spec.CloudCredentialSecretName == "" ||
		oldCluster.Spec.CloudCredentialSecretName == newCluster.Spec.CloudCredentialSecretName {
		return nil
	}

	secretNamespace, secretName := getCloudCredentialSecretInfo(newCluster.Namespace, newCluster.Spec.CloudCredentialSecretName)

	resp, err := p.sar.Create(request.Context, &authv1.SubjectAccessReview{
		Spec: authv1.SubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Verb:      "get",
				Version:   "v1",
				Resource:  "secrets",
				Group:     "",
				Name:      secretName,
				Namespace: secretNamespace,
			},
			User:   request.UserInfo.Username,
			Groups: request.UserInfo.Groups,
			Extra:  common.ConvertAuthnExtras(request.UserInfo.Extra),
			UID:    request.UserInfo.UID,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	if resp.Status.Allowed {
		return nil
	}

	response.Result = &metav1.Status{
		Status:  failureStatus,
		Message: resp.Status.Reason,
		Reason:  metav1.StatusReasonUnauthorized,
		Code:    http.StatusUnauthorized,
	}
	return nil
}

// getCloudCredentialSecretInfo returns the namespace and name of the secret based off the old cloud cred or new style
// cloud cred
func getCloudCredentialSecretInfo(namespace, name string) (string, string) {
	globalNS, globalName := kv.Split(name, ":")
	if globalName != "" && globalNS == globalNamespace {
		return globalNS, globalName
	}
	return namespace, name
}

func (p *provisioningAdmitter) validateClusterName(request *admission.Request, response *admissionv1.AdmissionResponse, cluster *v1.Cluster) error {
	if request.Operation != admissionv1.Create {
		return nil
	}

	// Look for an existing management cluster with the same name. If a management cluster with the given name does not
	// exist, then it should be checked that the provisioning cluster the user is trying to create is not of the form
	// "c-xxxxx" because names of that form are reserved for "legacy" management clusters.
	_, err := p.mgmtClusterClient.Get(cluster.Name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	if !isValidName(cluster.Name, cluster.Namespace, err == nil) {
		response.Result = &metav1.Status{
			Status:  failureStatus,
			Message: "cluster name must be 63 characters or fewer, must not begin with a hyphen, cannot be \"local\" nor of the form \"c-xxxxx\", and can only contain lowercase alphanumeric characters or ' - '",
			Reason:  metav1.StatusReasonInvalid,
			Code:    http.StatusUnprocessableEntity,
		}
	}

	return nil
}

func (p *provisioningAdmitter) validateMachinePoolNames(request *admission.Request, response *admissionv1.AdmissionResponse, cluster *v1.Cluster) error {
	if request.Operation != admissionv1.Create {
		return nil
	}

	if cluster.Spec.RKEConfig == nil {
		return nil
	}

	for _, pool := range cluster.Spec.RKEConfig.MachinePools {
		if len(pool.Name) > 63 {
			response.Result = &metav1.Status{
				Status:  failureStatus,
				Message: "pool name must be 63 characters or fewer",
				Reason:  metav1.StatusReasonInvalid,
				Code:    http.StatusUnprocessableEntity,
			}
			break
		}
	}

	return nil
}

// validatePSACT validate if the cluster and underlying secret are configured properly when PSACT is enabled or disabled
func (p *provisioningAdmitter) validatePSACT(request *admission.Request, response *admissionv1.AdmissionResponse, cluster *v1.Cluster) error {
	if cluster.Name == "local" || cluster.Spec.RKEConfig == nil {
		return nil
	}

	name := fmt.Sprintf(secretName, cluster.Name)
	mountPath := fmt.Sprintf(mountPath, getRuntime(cluster.Spec.KubernetesVersion))
	templateName := cluster.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName

	switch request.Operation {
	case admissionv1.Delete:
		_, err := p.secretCache.Get(cluster.Namespace, name)
		if err == nil {
			return fmt.Errorf("[provisioning cluster validator] the secret %s still exists in the cluster", name)
		}
		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("[provisioning cluster validator] failed to validate if the secret exists: %w", err)
		}
		return nil
	case admissionv1.Create, admissionv1.Update:
		if cluster.DeletionTimestamp != nil {
			return nil
		}
		if templateName == "" {
			// validate that the secret does not exist
			_, err := p.secretCache.Get(cluster.Namespace, name)
			if err == nil {
				return fmt.Errorf("[provisioning cluster validator] the secret %s still exists in the cluster", name)
			}
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("[provisioning cluster validator] failed to validate if the secret exists: %w", err)
			}
			// validate that the machineSelectorFile for PSA does not exist
			if machineSelectorFileExists(machineSelectorFileForPSA(name, mountPath, ""), cluster, true) {
				return fmt.Errorf("[provisioning cluster validator] machineSelectorFile for PSA should not be in the cluster Spec")
			}
			// validate that the flags are not set
			args := getKubeAPIServerArg(cluster)
			if value, ok := args[kubeAPIAdmissionConfigOption]; ok && value == mountPath {
				return fmt.Errorf("[provisioning cluster validator] admission-control-config-file under kube-apiserver-arg should not be set to %s", mountPath)
			}
		} else {
			parsedVersion, err := psa.GetClusterVersion(cluster.Spec.KubernetesVersion)
			if err != nil {
				return fmt.Errorf("[provisioning cluster validator] failed to parse cluster version: %w", err)
			}
			if parsedRangeLessThan123(parsedVersion) {
				response.Result = &metav1.Status{
					Status:  failureStatus,
					Message: "PodSecurityAdmissionConfigurationTemplate(PSACT) is only supported in k8s version 1.23 and above",
					Reason:  metav1.StatusReasonBadRequest,
					Code:    http.StatusBadRequest,
				}
				return nil
			}

			// validate that the psact exists
			if _, err := p.psactCache.Get(templateName); err != nil {
				if apierrors.IsNotFound(err) {
					response.Result = &metav1.Status{
						Status:  failureStatus,
						Message: err.Error(),
						Reason:  metav1.StatusReasonBadRequest,
						Code:    http.StatusBadRequest,
					}
					return nil
				}
				return fmt.Errorf("[provisioning cluster validator] failed to get PodSecurityAdmissionConfigurationTemplate: %w", err)
			}
			// validate that the secret for PSA exists
			secret, err := p.secretCache.Get(cluster.Namespace, name)
			if err != nil {
				return fmt.Errorf("[provisioning cluster validator] failed to get secret: %w", err)
			}
			// validate that the machineSelectorFile for PSA is set
			hash := sha256.Sum256(secret.Data[secretKey])
			if !machineSelectorFileExists(machineSelectorFileForPSA(name, mountPath, base64.StdEncoding.EncodeToString(hash[:])), cluster, false) {
				return fmt.Errorf("[provisioning cluster validator] machineSelectorFile for PSA should be in the cluster Spec")
			}
			// validate that the flags are set
			args := getKubeAPIServerArg(cluster)
			if val, ok := args[kubeAPIAdmissionConfigOption]; !ok || val != mountPath {
				return fmt.Errorf("[provisioning cluster validator] admission-control-config-file under kube-apiserver-arg should be set to %s", mountPath)
			}
		}
	}
	return nil
}

func validateAgentDeploymentCustomization(customization *v1.AgentDeploymentCustomization, path *field.Path) field.ErrorList {
	if customization == nil {
		return nil
	}
	var errList field.ErrorList

	errList = append(errList, validateAppendToleration(customization.AppendTolerations, path.Child("appendTolerations"))...)
	errList = append(errList, validateAffinity(customization.OverrideAffinity, path.Child("overrideAffinity"))...)

	return errList
}
func validateAffinity(overrideAffinity *k8sv1.Affinity, path *field.Path) field.ErrorList {
	if overrideAffinity == nil {
		return nil
	}
	var errList field.ErrorList

	if affinity := overrideAffinity.NodeAffinity; affinity != nil {
		errList = append(errList,
			validatePreferredSchedulingTerms(affinity.PreferredDuringSchedulingIgnoredDuringExecution,
				path.Child("nodeAffinity").Child("preferredDuringSchedulingIgnoredDuringExecution"))...,
		)
		errList = append(errList,
			validateNodeSelector(affinity.RequiredDuringSchedulingIgnoredDuringExecution,
				path.Child("nodeAffinity").Child("requiredDuringSchedulingIgnoredDuringExecution"))...,
		)
	}

	if podAffinity := overrideAffinity.PodAffinity; podAffinity != nil {
		errList = append(errList, validatePodAffinityTerms(podAffinity.RequiredDuringSchedulingIgnoredDuringExecution,
			path.Child("podAffinity").Child("requiredDuringSchedulingIgnoredDuringExecution"))...)

		errList = append(errList, validateWeightedPodAffinityTerms(podAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
			path.Child("podAffinity").Child("preferredDuringSchedulingIgnoredDuringExecution"))...)
	}

	if podAntiAffinity := overrideAffinity.PodAntiAffinity; podAntiAffinity != nil {
		errList = append(errList, validatePodAffinityTerms(podAntiAffinity.RequiredDuringSchedulingIgnoredDuringExecution,
			path.Child("podAntiAffinity").Child("requiredDuringSchedulingIgnoredDuringExecution"))...)

		errList = append(errList, validateWeightedPodAffinityTerms(podAntiAffinity.PreferredDuringSchedulingIgnoredDuringExecution,
			path.Child("podAntiAffinity").Child("preferredDuringSchedulingIgnoredDuringExecution"))...)

	}
	return errList
}

func validatePodAffinityTerms(terms []k8sv1.PodAffinityTerm, path *field.Path) field.ErrorList {
	var errList field.ErrorList

	for k, v := range terms {
		errList = append(errList, validatePodAffinityTerm(v, path.Index(k))...)
	}
	return errList
}

func validateWeightedPodAffinityTerms(weightedPodAffinityTerm []k8sv1.WeightedPodAffinityTerm, path *field.Path) field.ErrorList {
	var errList field.ErrorList
	for k, v := range weightedPodAffinityTerm {
		errList = append(errList, validatePodAffinityTerm(v.PodAffinityTerm, path.Index(k).Child("podAffinityTerm"))...)
	}
	return errList
}

func validatePodAffinityTerm(podAffinityTerm k8sv1.PodAffinityTerm, path *field.Path) field.ErrorList {
	var errList field.ErrorList
	errList = append(errList, validateLabelSelector(podAffinityTerm.LabelSelector, path.Child("labelSelector"))...)
	errList = append(errList, validateLabelSelector(podAffinityTerm.NamespaceSelector, path.Child("namespaceSelector"))...)
	return errList
}

func validateLabelSelector(labelSelector *metav1.LabelSelector, path *field.Path) field.ErrorList {
	return validation.ValidateLabelSelector(labelSelector, validation.LabelSelectorValidationOptions{}, path)

}

func validatePreferredSchedulingTerms(schedulingTerms []k8sv1.PreferredSchedulingTerm, path *field.Path) field.ErrorList {
	var errList field.ErrorList

	for k, v := range schedulingTerms {
		errList = append(errList, validateNodeSelectorTerm(v.Preference, path.Index(k).Child("preferences"))...)
	}
	return errList
}

func validateNodeSelector(nodeSelector *k8sv1.NodeSelector, path *field.Path) field.ErrorList {
	if nodeSelector == nil {
		return nil
	}
	var errList field.ErrorList
	nodeSelectorPath := path.Child("nodeSelectorTerms")
	for k, v := range nodeSelector.NodeSelectorTerms {
		errList = append(errList, validateNodeSelectorTerm(v, nodeSelectorPath.Index(k))...)
	}
	return errList
}

func validateNodeSelectorTerm(term k8sv1.NodeSelectorTerm, path *field.Path) field.ErrorList {
	var errList field.ErrorList
	errList = append(errList, validateNodeSelectorRequirements(term.MatchFields, path.Child("matchFields"))...)
	errList = append(errList, validateNodeSelectorRequirements(term.MatchExpressions, path.Child("matchExpressions"))...)
	return errList
}

// validateNodeSelectorRequirements Validates the NodeSelectors
// at the moment it only validates the key by calling validation.ValidateLabelName.
func validateNodeSelectorRequirements(selector []k8sv1.NodeSelectorRequirement, path *field.Path) field.ErrorList {
	var errList field.ErrorList
	for k, s := range selector {
		errList = append(errList, validation.ValidateLabelName(s.Key, path.Index(k).Child("key"))...)
	}
	return errList
}

// validateAppendToleration validate if tolerations follows the k8s standards
// at the moment it only validates the key by calling validation.ValidateLabelName.
func validateAppendToleration(toleration []k8sv1.Toleration, path *field.Path) field.ErrorList {
	var errList field.ErrorList
	for k, s := range toleration {
		errList = append(errList, validation.ValidateLabelName(s.Key, path.Index(k))...)
	}
	return errList
}

// errorListToStatus convert an errorList to failure status, it breaks a line for each entry and adds a * in front
func errorListToStatus(errList field.ErrorList) *metav1.Status {
	if len(errList) == 0 {
		return nil
	}
	var builder strings.Builder
	builder.WriteString("* ")
	for i, fieldErr := range errList {
		builder.WriteString(fieldErr.Error())
		if i != len(errList)-1 {
			builder.WriteString("\n* ")
		}
	}
	return &metav1.Status{
		Status:  failureStatus,
		Message: builder.String(),
		Reason:  metav1.StatusReasonInvalid,
		Code:    http.StatusUnprocessableEntity,
	}
}

func validateACEConfig(cluster *v1.Cluster) *metav1.Status {
	if cluster.Spec.RKEConfig != nil && cluster.Spec.LocalClusterAuthEndpoint.Enabled && cluster.Spec.LocalClusterAuthEndpoint.CACerts != "" && cluster.Spec.LocalClusterAuthEndpoint.FQDN == "" {
		return &metav1.Status{
			Status:  failureStatus,
			Message: "CACerts defined but FQDN is not defined",
			Reason:  metav1.StatusReasonInvalid,
			Code:    http.StatusUnprocessableEntity,
		}
	}

	return nil
}

func isValidName(clusterName, clusterNamespace string, clusterExists bool) bool {
	// A provisioning cluster with name "local" is only expected to be created in the "fleet-local" namespace.
	if clusterName == "local" {
		return clusterNamespace == "fleet-local"
	}

	if mgmtNameRegex.MatchString(clusterName) {
		// A provisioning cluster with a name of the form "c-xxxxx" is expected to be created if a management cluster
		// of the same name already exists because Rancher will create such a provisioning cluster.
		// Therefore, a provisioning cluster with a name of the form "c-xxxxx" is only valid if its management cluster was found under the same name.
		return clusterExists
	}

	// Even though the name of the provisioning cluster object can be 253 characters, the name of the cluster is put in
	// various labels, by Rancher controllers and CAPI controllers. Because of this, the name of the cluster object should
	// be limited to 63 characters instead. Additionally, a provisioning cluster with a name that does not conform to
	// RFC-1123 will fail to deploy required fleet components and should not be accepted.
	return len(clusterName) <= 63 && fleetNameRegex.MatchString(clusterName)
}
