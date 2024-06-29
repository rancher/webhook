package cluster

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"golang.org/x/exp/slices"

	"github.com/blang/semver"
	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/patch"
	psa "github.com/rancher/webhook/pkg/podsecurityadmission"
	"github.com/rancher/wrangler/v2/pkg/data/convert"
	corecontroller "github.com/rancher/wrangler/v2/pkg/generated/controllers/core/v1"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

const (
	// KubeAPIAdmissionConfigOption is the option name in kube-apiserver for the admission control configuration file
	kubeAPIAdmissionConfigOption = "admission-control-config-file"
	// secretName is the naming pattern of the secret which contains the admission control configuration file
	secretName = "%s-admission-configuration-psact"
	// SecretKey is the key of the item holding the admission control configuration file in the secret
	secretKey = "admission-config-psact"
	// MountPath is where the admission control configuration file will be mounted in the control plane nodes
	mountPath = "/etc/rancher/%s/config/rancher-psact.yaml"

	controlPlaneRoleLabel            = "rke.cattle.io/control-plane-role"
	secretAnnotation                 = "rke.cattle.io/object-authorized-for-clusters"
	allowDynamicSchemaDropAnnotation = "provisioning.cattle.io/allow-dynamic-schema-drop"
	runtimeK3S                       = "k3s"
	runtimeRKE2                      = "rke2"
	runtimeRKE                       = "rke"
)

var (
	parsedRangeLessThan123 = semver.MustParseRange("< 1.23.0-rancher0")
	parsedRangeLessThan125 = semver.MustParseRange("< 1.25.0-rancher0")
)

var gvr = schema.GroupVersionResource{
	Group:    "provisioning.cattle.io",
	Version:  "v1",
	Resource: "clusters",
}

// ProvisioningClusterMutator implements admission.MutatingAdmissionWebhook.
type ProvisioningClusterMutator struct {
	secret corecontroller.SecretController
	psact  v3.PodSecurityAdmissionConfigurationTemplateCache
}

// NewProvisioningClusterMutator returns a new mutator for provisioning clusters
func NewProvisioningClusterMutator(secret corecontroller.SecretController, psact v3.PodSecurityAdmissionConfigurationTemplateCache) *ProvisioningClusterMutator {
	return &ProvisioningClusterMutator{
		secret: secret,
		psact:  psact,
	}
}

// GVR returns the GroupVersionKind for this CRD.
func (m *ProvisioningClusterMutator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this mutator.
func (m *ProvisioningClusterMutator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update, admissionregistrationv1.Delete}
}

// MutatingWebhook returns the MutatingWebhook used for this CRD.
func (m *ProvisioningClusterMutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.MutatingWebhook {
	mutatingWebhook := admission.NewDefaultMutatingWebhook(m, clientConfig, admissionregistrationv1.NamespacedScope, m.Operations())
	mutatingWebhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNoneOnDryRun)
	return []admissionregistrationv1.MutatingWebhook{*mutatingWebhook}
}

// Admit is the entrypoint for the mutator. Admit will return an error if it unable to process the request.
func (m *ProvisioningClusterMutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if request.DryRun != nil && *request.DryRun {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}

	listTrace := trace.New("provisioningCluster Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldCluster, cluster, err := objectsv1.ClusterOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}

	// Re-marshal the cluster for generating the JSON patch. If the webhook's provisioning cluster CRD is out of date, the
	// patch will unintentionally drop new (unknown) fields. This ensures the patch is generated based solely on the
	// patches we expect.
	clusterJSON, err := json.Marshal(cluster)
	if err != nil {
		return nil, err
	}

	if request.Operation == admissionv1.Create {
		// Set Annotation on the cluster
		annotations := cluster.GetAnnotations()
		if annotations == nil {
			annotations = map[string]string{}
		}
		annotations[auth.CreatorIDAnn] = request.UserInfo.Username
		cluster.SetAnnotations(annotations)
	}

	response, err := m.handlePSACT(request, cluster)
	if err != nil {
		return nil, err
	}
	if response.Result != nil {
		return response, nil
	}

	if request.Operation == admissionv1.Update {
		response = m.handleDynamicSchemaDrop(request, oldCluster, cluster)
		if response.Result != nil {
			return response, nil
		}
	}

	response.Allowed = true
	if err = patch.CreatePatch(clusterJSON, cluster, response); err != nil {
		return nil, fmt.Errorf("failed to create patch: %w", err)
	}
	return response, nil
}

// handleDynamicSchemaDrop watches for provisioning cluster updates, and reinserts the previous value of the
// dynamicSchemaSpec field for a machine pool if the "provisioning.cattle.io/allow-dynamic-schema-drop" annotation is
// not present and true on the cluster. If the value of the annotation is true, no mutation is performed.
func (m *ProvisioningClusterMutator) handleDynamicSchemaDrop(request *admission.Request, oldCluster, cluster *v1.Cluster) *admissionv1.AdmissionResponse {
	if cluster.Name == "local" || cluster.Spec.RKEConfig == nil {
		return admission.ResponseAllowed()
	}

	if cluster.Annotations[allowDynamicSchemaDropAnnotation] == "true" {
		return admission.ResponseAllowed()
	}

	oldClusterPools := map[string]*v1.RKEMachinePool{}
	for _, mp := range oldCluster.Spec.RKEConfig.MachinePools {
		oldClusterPools[mp.Name] = &mp
	}

	for i, newPool := range cluster.Spec.RKEConfig.MachinePools {
		oldPool, ok := oldClusterPools[newPool.Name]
		if !ok {
			logrus.Debugf("[%s] new machine pool: %s, skipping validation of dynamic schema spec", request.UID, newPool.Name)
			continue
		}
		if oldPool.DynamicSchemaSpec != "" && newPool.DynamicSchemaSpec == "" {
			logrus.Debugf("provisioning cluster %s/%s machine pool %s dynamic schema spec mutated without supplying annotation %s, reverting", cluster.Namespace, cluster.Name, newPool.Name, allowDynamicSchemaDropAnnotation)
			cluster.Spec.RKEConfig.MachinePools[i].DynamicSchemaSpec = oldPool.DynamicSchemaSpec
		}
	}
	return admission.ResponseAllowed()
}

// handlePSACT updates the cluster and an underlying secret to support PSACT.
// If a PSACT is set in the cluster, handlePSACT generates an admission configuration file, mounts the file into a secret,
// updates the cluster's spec to mount the secret to the control plane nodes, and configures kube-apisever to use the admission configuration file;
// If a PSACT is unset in the cluster, handlePSACT does the cleanup for both the secret and cluster's spec.
func (m *ProvisioningClusterMutator) handlePSACT(request *admission.Request, cluster *v1.Cluster) (*admissionv1.AdmissionResponse, error) {
	if cluster.Name == "local" || cluster.Spec.RKEConfig == nil {
		return admission.ResponseAllowed(), nil
	}
	parsedVersion, err := psa.GetClusterVersion(cluster.Spec.KubernetesVersion)
	if err != nil {
		return nil, fmt.Errorf("[provisioning cluster mutator] failed to parse cluster version: %w", err)
	}
	if parsedRangeLessThan123(parsedVersion) {
		return admission.ResponseAllowed(), nil
	}

	secretName := fmt.Sprintf(secretName, cluster.Name)
	mountPath := fmt.Sprintf(mountPath, getRuntime(cluster.Spec.KubernetesVersion))
	templateName := cluster.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName

	switch request.Operation {
	case admissionv1.Delete:
		err := m.secret.Delete(cluster.Namespace, secretName, &metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("[provisioning cluster mutator] failed to delete the secret: %w", err)
		}
	case admissionv1.Create, admissionv1.Update:
		if cluster.DeletionTimestamp != nil {
			return admission.ResponseAllowed(), nil
		}
		if templateName == "" {
			err := m.secret.Delete(cluster.Namespace, secretName, &metav1.DeleteOptions{})
			if err != nil && !apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("[provisioning cluster mutator] failed to delete the secret: %w", err)
			}
			// drop relevant fields if they exist in the cluster
			dropMachineSelectorFile(machineSelectorFileForPSA(secretName, mountPath, ""), cluster, true)
			args := getKubeAPIServerArg(cluster)
			if args[kubeAPIAdmissionConfigOption] == mountPath {
				delete(args, kubeAPIAdmissionConfigOption)
				setKubeAPIServerArg(args, cluster)
			}
		} else {
			// Now, handle the case of PSACT being set when creating or updating the cluster
			template, err := m.psact.Get(templateName)
			if err != nil {
				if apierrors.IsNotFound(err) {
					return admission.ResponseBadRequest(err.Error()), nil
				}
				return nil, fmt.Errorf("[provisioning cluster mutator] failed to get psact: %w", err)
			}
			fileContent, err := psa.GenerateAdmissionConfigFile(template, cluster.Spec.KubernetesVersion)
			if err != nil {
				return nil, fmt.Errorf("[provisioning cluster mutator] failed to generate admission configuration from PSACT [%s]: %w", templateName, err)
			}
			anno := map[string]string{
				secretAnnotation: cluster.Name,
			}
			data := map[string][]byte{
				secretKey: fileContent,
			}
			err = m.ensureSecret(cluster.Namespace, secretName, data, anno)
			if err != nil {
				return nil, fmt.Errorf("[provisioning cluster mutator] failed to create or update the secret for the admission configuration file: %w", err)
			}
			// drop then set relevant fields if they exist in the cluster
			dropMachineSelectorFile(machineSelectorFileForPSA(secretName, mountPath, ""), cluster, true)
			hash := sha256.Sum256(fileContent)
			addMachineSelectorFile(machineSelectorFileForPSA(secretName, mountPath, base64.StdEncoding.EncodeToString(hash[:])), cluster)
			args := getKubeAPIServerArg(cluster)
			args[kubeAPIAdmissionConfigOption] = mountPath
			setKubeAPIServerArg(args, cluster)
		}
	}
	return admission.ResponseAllowed(), nil
}

// ensureSecret creates or updates a secret based on the provided information.
func (m *ProvisioningClusterMutator) ensureSecret(namespace, name string, data map[string][]byte, annotations map[string]string) error {
	if namespace == "" || name == "" {
		return fmt.Errorf("namespace and name are required")
	}
	existing, err := m.secret.Cache().Get(namespace, name)
	if err != nil && !apierrors.IsNotFound(err) {
		return err
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
		Type: corev1.SecretTypeOpaque,
	}
	if annotations != nil {
		secret.Annotations = annotations
	}
	if existing == nil {
		_, err = m.secret.Create(secret)
		return err
	}
	if !reflect.DeepEqual(existing.Data, secret.Data) {
		existing.Data = data
		_, err = m.secret.Update(existing)
		return err
	}
	return nil
}

// getKubeAPIServerArg returns a map representation of the value of kube-apiserver-arg from the cluster's MachineGlobalConfig.
// An empty map is returned if kube-apiserver-arg is not set in the cluster.
func getKubeAPIServerArg(cluster *v1.Cluster) map[string]string {
	if cluster.Spec.RKEConfig.MachineGlobalConfig.Data != nil {
		return toMap(cluster.Spec.RKEConfig.MachineGlobalConfig.Data["kube-apiserver-arg"])
	}
	return map[string]string{}
}

func toMap(input interface{}) map[string]string {
	args := map[string]string{}
	parsed := convert.ToInterfaceSlice(input)
	for _, arg := range parsed {
		key, val, found := strings.Cut(convert.ToString(arg), "=")
		if !found {
			logrus.Debugf("skipping argument [%s] which does not have right format", arg)
			continue
		}
		args[key] = val
	}
	return args
}

// setKubeAPIServerArg uses the provided arg to overwrite the value of kube-apiserver-arg under the cluster's MachineGlobalConfig.
// If the provided arg is an empty map, setKubeAPIServerArg removes the existing kube-apiserver-arg from the cluster's MachineGlobalConfig.
func setKubeAPIServerArg(arg map[string]string, cluster *v1.Cluster) {
	if len(arg) == 0 {
		delete(cluster.Spec.RKEConfig.MachineGlobalConfig.Data, "kube-apiserver-arg")
		return
	}
	parsed := make([]any, 0, len(arg))
	for key, val := range arg {
		parsed = append(parsed, fmt.Sprintf("%s=%s", key, val))
	}
	if cluster.Spec.RKEConfig.MachineGlobalConfig.Data == nil {
		cluster.Spec.RKEConfig.MachineGlobalConfig.Data = make(map[string]interface{})
	}
	cluster.Spec.RKEConfig.MachineGlobalConfig.Data["kube-apiserver-arg"] = parsed
}

// machineSelectorFileForPSA generates an RKEProvisioningFiles that mounts the secret which contains
// the generated admission configuration file to the control plane node
func machineSelectorFileForPSA(secretName, mountPath, hash string) *rkev1.RKEProvisioningFiles {
	// TODO: change args to differ from consts
	return &rkev1.RKEProvisioningFiles{
		MachineLabelSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				controlPlaneRoleLabel: "true",
			},
		},
		FileSources: []rkev1.ProvisioningFileSource{
			{
				Secret: rkev1.K8sObjectFileSource{
					Name: secretName,
					Items: []rkev1.KeyToPath{
						{
							Key:  secretKey,
							Path: mountPath,
							Hash: hash,
						},
					},
				},
			},
		},
	}
}

// addMachineSelectorFile adds the provided RKEProvisioningFiles to the cluster's MachineSelectorFiles list.
// It is a no-op if the provided RKEProvisioningFiles already exist in the cluster.
func addMachineSelectorFile(file *rkev1.RKEProvisioningFiles, cluster *v1.Cluster) {
	for _, item := range cluster.Spec.RKEConfig.MachineSelectorFiles {
		if equality.Semantic.DeepEqual(file, &item) {
			return
		}
	}
	cluster.Spec.RKEConfig.MachineSelectorFiles = append(cluster.Spec.RKEConfig.MachineSelectorFiles, *file)
}

// dropMachineSelectorFile removes the provided RKEProvisioningFiles from the cluster if it is found in the cluster.
func dropMachineSelectorFile(file *rkev1.RKEProvisioningFiles, cluster *v1.Cluster, ignoreValueCheck bool) {
	source := cluster.Spec.RKEConfig.MachineSelectorFiles
	if ignoreValueCheck {
		cleanupHash(file)
	}
	// traverse the slice backward for faster lookup because the target is usually the last item in the slice
	for i := len(source) - 1; i >= 0; i-- {
		fromCluster := &source[i]
		if ignoreValueCheck {
			fromCluster = fromCluster.DeepCopy()
			cleanupHash(fromCluster)
		}
		if equality.Semantic.DeepEqual(file, fromCluster) {
			if len(source) == 1 {
				cluster.Spec.RKEConfig.MachineSelectorFiles = nil
				break
			}
			cluster.Spec.RKEConfig.MachineSelectorFiles = slices.Delete(source, i, i+1)
			break
		}
	}
}

// MachineSelectorFileExists returns a boolean to indicate if the provided RKEProvisioningFiles exist in the provided cluster.
func machineSelectorFileExists(file *rkev1.RKEProvisioningFiles, cluster *v1.Cluster, ignoreValueCheck bool) bool {
	if ignoreValueCheck {
		cleanupHash(file)
	}
	for _, item := range cluster.Spec.RKEConfig.MachineSelectorFiles {
		fromCluster := &item
		if ignoreValueCheck {
			fromCluster = fromCluster.DeepCopy()
			cleanupHash(fromCluster)
		}
		if equality.Semantic.DeepEqual(file, fromCluster) {
			return true
		}
	}
	return false
}

// GetRuntime returns the runtime of a cluster by checking its k8s version.
func getRuntime(kubernetesVersion string) string {
	switch {
	case strings.Contains(kubernetesVersion, runtimeK3S):
		return runtimeK3S
	case strings.Contains(kubernetesVersion, runtimeRKE2):
		return runtimeRKE2
	case strings.Contains(kubernetesVersion, "-rancher"):
		return runtimeRKE
	default:
		return ""
	}
}

// cleanupHash unsets the value of the field Hash in the RKEProvisioningFiles
func cleanupHash(file *rkev1.RKEProvisioningFiles) {
	for i, source := range file.FileSources {
		for j := range source.Secret.Items {
			file.FileSources[i].Secret.Items[j].Hash = ""
		}
		for j := range source.ConfigMap.Items {
			file.FileSources[i].ConfigMap.Items[j].Hash = ""
		}
	}
}
