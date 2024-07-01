package cluster

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"slices"

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
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/trace"
)

const (
	globalNamespace         = "cattle-global-data"
	systemAgentVarDirEnvVar = "CATTLE_AGENT_VAR_DIR"
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

		if err := p.validateCloudCredentialAccess(request, response, oldCluster, cluster); err != nil || response.Result != nil {
			return response, err
		}

		if response = p.validateAgentEnvVars(request, oldCluster, cluster); response.Result != nil {
			return response, err
		}

		if response = p.validateDataDirectories(request, oldCluster, cluster); response.Result != nil {
			return response, err
		}
	}

	if err := p.validatePSACT(request, response, cluster); err != nil || response.Result != nil {
		return response, err
	}

	response.Allowed = true
	return response, nil
}

// validateAgentEnvVars will validate the provisioning cluster object's AgentEnvVars, ensuring that the
// "CATTLE_AGENT_VAR_DIR" env var is not allowed to be added to an existing cluster, or set upon create for a new
// cluster.
func (p *provisioningAdmitter) validateAgentEnvVars(request *admission.Request, oldCluster, newCluster *v1.Cluster) *admissionv1.AdmissionResponse {
	if newCluster.Spec.RKEConfig == nil {
		return admission.ResponseAllowed()
	}
	if request.Operation == admissionv1.Create {
		if slices.ContainsFunc(newCluster.Spec.AgentEnvVars, func(envVar rkev1.EnvVar) bool {
			return envVar.Name == systemAgentVarDirEnvVar
		}) {
			return admission.ResponseBadRequest(
				fmt.Sprintf(`"%s" cannot be set within "cluster.Spec.RKEConfig.AgentEnvVars": use "cluster.Spec.RKEConfig.DataDirectories.SystemAgent"`, systemAgentVarDirEnvVar))
		}
		return admission.ResponseAllowed()
	}
	if request.Operation == admissionv1.Update {
		var oldCount, newCount int
		for _, envVar := range oldCluster.Spec.AgentEnvVars {
			if envVar.Name == systemAgentVarDirEnvVar {
				oldCount++
			}
		}
		for _, envVar := range newCluster.Spec.AgentEnvVars {
			if envVar.Name == systemAgentVarDirEnvVar {
				newCount++
			}
		}
		if newCount > oldCount {
			return admission.ResponseBadRequest(
				fmt.Sprintf(`"%s" cannot be set within "cluster.Spec.RKEConfig.AgentEnvVars": use "cluster.Spec.RKEConfig.DataDirectories.SystemAgent"`, systemAgentVarDirEnvVar))
		}
	}

	return admission.ResponseAllowed()
}

// validateDataDirectories will validate updates to the cluster object to ensure the data directories are not changed.
// The only exception when a data directory is allowed to be changed is if cluster.Spec.AgentEnvVars has an env var with
// a name of "CATTLE_AGENT_VAR_DIR", which Rancher will perform a one-time migration to set the
// cluster.Spec.RKEConfig.DataDirectories.SystemAgent field for the cluster. validateAgentEnvVars will ensure
// "CATTLE_AGENT_VAR_DIR" is not added, so this exception only applies to the one-time Rancher migration.
func (p *provisioningAdmitter) validateDataDirectories(request *admission.Request, oldCluster, newCluster *v1.Cluster) *admissionv1.AdmissionResponse {
	if request.Operation != admissionv1.Update {
		return admission.ResponseAllowed()
	}
	if newCluster.Spec.RKEConfig == nil {
		return admission.ResponseAllowed()
	}
	oldSystemAgentVarDirEnvVars := slices.DeleteFunc(slices.Clone(oldCluster.Spec.AgentEnvVars), func(envVar rkev1.EnvVar) bool {
		return envVar.Name != systemAgentVarDirEnvVar
	})
	// will be true up until rancher performs one time migration to set SystemAgent data directory if env var was previously set
	if len(oldSystemAgentVarDirEnvVars) > 0 {
		newSystemAgentVarDirEnvVars := slices.DeleteFunc(slices.Clone(newCluster.Spec.AgentEnvVars), func(envVar rkev1.EnvVar) bool {
			return envVar.Name != systemAgentVarDirEnvVar
		})
		if !reflect.DeepEqual(newSystemAgentVarDirEnvVars, oldSystemAgentVarDirEnvVars) || oldCluster.Spec.RKEConfig.DataDirectories.SystemAgent != newCluster.Spec.RKEConfig.DataDirectories.SystemAgent {
			if newCluster.Spec.RKEConfig.DataDirectories.SystemAgent != oldSystemAgentVarDirEnvVars[len(oldSystemAgentVarDirEnvVars)-1].Value {
				// only valid during migration
				return admission.ResponseBadRequest(
					fmt.Sprintf(`"%s" cannot be set within "cluster.Spec.RKEConfig.AgentEnvVars": use "cluster.Spec.RKEConfig.DataDirectories.SystemAgent"`, systemAgentVarDirEnvVar))
			}
		}
	} else if oldCluster.Spec.RKEConfig.DataDirectories.SystemAgent != newCluster.Spec.RKEConfig.DataDirectories.SystemAgent {
		return admission.ResponseBadRequest("SystemAgent data directory cannot be changed after cluster creation")
	}
	if oldCluster.Spec.RKEConfig.DataDirectories.Provisioning != newCluster.Spec.RKEConfig.DataDirectories.Provisioning {
		return admission.ResponseBadRequest("Provisioning data directory cannot be changed after cluster creation")
	}
	if oldCluster.Spec.RKEConfig.DataDirectories.K8sDistro != newCluster.Spec.RKEConfig.DataDirectories.K8sDistro {
		return admission.ResponseBadRequest("Distro data directory cannot be changed after cluster creation")
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
		Status:  "Failure",
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
			Status:  "Failure",
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
				Status:  "Failure",
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
					Status:  "Failure",
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
						Status:  "Failure",
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

func validateACEConfig(cluster *v1.Cluster) *metav1.Status {
	if cluster.Spec.RKEConfig != nil && cluster.Spec.LocalClusterAuthEndpoint.Enabled && cluster.Spec.LocalClusterAuthEndpoint.CACerts != "" && cluster.Spec.LocalClusterAuthEndpoint.FQDN == "" {
		return &metav1.Status{
			Status:  "Failure",
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
