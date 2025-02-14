package cluster

import (
	"encoding/json"
	"fmt"
	"reflect"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/patch"
	psa "github.com/rancher/webhook/pkg/podsecurityadmission"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var managementGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "clusters",
}

func NewManagementClusterMutator(cache v3.PodSecurityAdmissionConfigurationTemplateCache) *ManagementClusterMutator {
	return &ManagementClusterMutator{
		psact: cache,
	}
}

// ManagementClusterMutator implements admission.MutatingAdmissionWebhook.
type ManagementClusterMutator struct {
	psact v3.PodSecurityAdmissionConfigurationTemplateCache
}

// GVR returns the GroupVersionKind for this CRD.
func (m *ManagementClusterMutator) GVR() schema.GroupVersionResource {
	return managementGVR
}

// Operations returns list of operations handled by this mutator.
func (m *ManagementClusterMutator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update}
}

// MutatingWebhook returns the MutatingWebhook used for this CRD.
func (m *ManagementClusterMutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.MutatingWebhook {
	mutatingWebhook := admission.NewDefaultMutatingWebhook(m, clientConfig, admissionregistrationv1.ClusterScope, m.Operations())
	mutatingWebhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNoneOnDryRun)
	return []admissionregistrationv1.MutatingWebhook{*mutatingWebhook}
}

// Admit is the entrypoint for the mutator. Admit will return an error if it is unable to process the request.
func (m *ManagementClusterMutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if request.DryRun != nil && *request.DryRun {
		return admission.ResponseAllowed(), nil
	}
	oldCluster, newCluster, err := objectsv3.ClusterOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get old and new clusters from request: %w", err)
	}
	newClusterRaw, err := json.Marshal(newCluster)
	if err != nil {
		return nil, fmt.Errorf("unable to re-marshal new cluster: %w", err)
	}

	err = m.mutatePSACT(oldCluster, newCluster, request.Operation)
	if err != nil {
		return nil, fmt.Errorf("failed to mutate PSACT: %w", err)
	}

	m.mutateVersionManagement(newCluster, request.Operation)

	response := &admissionv1.AdmissionResponse{}
	// we use the re-marshalled new cluster to make sure that the patch doesn't drop "unknown" fields which were
	// in the json, but not in the cluster struct. This can occur due to out of date RKE versions
	if err := patch.CreatePatch(newClusterRaw, newCluster, response); err != nil {
		return nil, fmt.Errorf("failed to create patch: %w", err)
	}
	response.Allowed = true
	return response, nil
}

// mutatePSACT updates the newCluster's Pod Security Admission (PSA) configuration based on changes to
// the cluster's `DefaultPodSecurityAdmissionConfigurationTemplateName`.
// It applies or removes the PSA plugin configuration depending on the operation and the current cluster state.
func (m *ManagementClusterMutator) mutatePSACT(oldCluster, newCluster *apisv3.Cluster, operation admissionv1.Operation) error {
	// no need to mutate the local cluster, or imported cluster which represents a KEv2 cluster (GKE/EKS/AKS) or v1 Provisioning Cluster
	if newCluster.Name == "local" || newCluster.Spec.RancherKubernetesEngineConfig == nil {
		return nil
	}
	if operation != admissionv1.Update && operation != admissionv1.Create {
		return nil
	}
	newTemplateName := newCluster.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName
	oldTemplateName := oldCluster.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName

	// If the template is set(or changed), update the cluster with the new template's content
	if newTemplateName != "" {
		err := m.setPSAConfig(newCluster)
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to set PSAconfig: %w", err)
		}
	} else {
		if operation == admissionv1.Update {
			// The case of dropping the PSACT in the UPDATE operation:
			// It is a valid use case where user switches from using PSACT to putting a PluginConfig for PSA under kube-api.AdmissionConfiguration,
			// but it is not a valid use case where the PluginConfig for PSA has the same content as the one in the previous-set PSACT,
			// so we need to drop it in this case.
			if oldTemplateName != "" {
				newConfig, found := psa.GetPluginConfigFromCluster(newCluster)
				if found {
					// found means there is a Plugin Config for PSA under the kube-api.admission_configuration section
					oldConfig, _ := psa.GetPluginConfigFromCluster(oldCluster)
					if reflect.DeepEqual(newConfig, oldConfig) {
						psa.DropPSAPluginConfigFromAdmissionConfig(newCluster)
					}
				}
			}
		}
	}
	return nil
}

// setPSAConfig makes sure that the PodSecurity config under the admission_configuration section matches the
// PodSecurityAdmissionConfigurationTemplate set in the cluster
func (m *ManagementClusterMutator) setPSAConfig(cluster *apisv3.Cluster) error {
	template, err := m.psact.Get(cluster.Spec.DefaultPodSecurityAdmissionConfigurationTemplateName)
	if err != nil {
		return fmt.Errorf("failed to get PodSecurityAdmissionConfigurationTemplate: %w", err)
	}
	plugin, err := psa.GetPluginConfigFromTemplate(template, cluster.Spec.RancherKubernetesEngineConfig.Version)
	if err != nil {
		return fmt.Errorf("failed to get plugin config from template: %w", err)
	}
	admissionConfig := psa.GetAdmissionConfigFromCluster(cluster)
	found := false
	for i, item := range admissionConfig.Plugins {
		if item.Name == "PodSecurity" {
			admissionConfig.Plugins[i] = plugin
			found = true
			break
		}
	}
	if !found {
		admissionConfig.Plugins = append(admissionConfig.Plugins, plugin)
	}
	// now put the new admissionConfig back to the Cluster object
	cluster.Spec.RancherKubernetesEngineConfig.Services.KubeAPI.AdmissionConfiguration = admissionConfig
	return nil
}

// mutateVersionManagement set the annotation for version management if it is missing or has empty value on an imported RKE2/K3s cluster
func (m *ManagementClusterMutator) mutateVersionManagement(cluster *apisv3.Cluster, operation admissionv1.Operation) {
	if operation != admissionv1.Update && operation != admissionv1.Create {
		return
	}
	if cluster.Status.Driver != apisv3.ClusterDriverRke2 && cluster.Status.Driver != apisv3.ClusterDriverK3s {
		return
	}

	val, ok := cluster.Annotations[VersionManagementAnno]
	if !ok || val == "" {
		if cluster.Annotations == nil {
			cluster.Annotations = make(map[string]string)
		}
		cluster.Annotations[VersionManagementAnno] = "system-default"
	}
	return
}
