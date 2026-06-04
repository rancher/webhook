package cluster

import (
	"encoding/json"
	"fmt"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/patch"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var managementGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "clusters",
}

func NewManagementClusterMutator() *ManagementClusterMutator {
	return &ManagementClusterMutator{}
}

// ManagementClusterMutator implements admission.MutatingAdmissionWebhook.
type ManagementClusterMutator struct {
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
	_, newCluster, err := objectsv3.ClusterOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get old and new clusters from request: %w", err)
	}
	newClusterRaw, err := json.Marshal(newCluster)
	if err != nil {
		return nil, fmt.Errorf("unable to re-marshal new cluster: %w", err)
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
}
