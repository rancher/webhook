package machinedeployment

import (
	"encoding/json"
	"fmt"

	"github.com/rancher/webhook/pkg/admission"
	clusterv1beta1 "github.com/rancher/webhook/pkg/generated/controllers/cluster.x-k8s.io/v1beta1"
	provv1 "github.com/rancher/webhook/pkg/generated/controllers/provisioning.cattle.io/v1"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/trace"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
)

// MachineDeploymentMutator implements admission.MutatingAdmissionWebhook.
type MachineDeploymentMutator struct {
	// MachineDeployment cache for retrieving MachineDeployment objects
	MachineDeploymentCache clusterv1beta1.MachineDeploymentCache
	// Provisioning cluster cache for retrieving provisioning Cluster objects
	ProvisioningClusterCache provv1.ClusterCache
	// Provisioning cluster client for updating provisioning Cluster objects
	ProvisioningClusterClient provv1.ClusterClient
}

// NewMachineDeploymentMutator returns a new mutator for MachineDeployment.
func NewMachineDeploymentMutator(machineDeploymentCache clusterv1beta1.MachineDeploymentCache, provClusterCache provv1.ClusterCache, provClusterClient provv1.ClusterClient) *MachineDeploymentMutator {
	return &MachineDeploymentMutator{
		MachineDeploymentCache:    machineDeploymentCache,
		ProvisioningClusterCache:  provClusterCache,
		ProvisioningClusterClient: provClusterClient,
	}
}

// GVR returns the GroupVersionKind for this CRD.
func (m *MachineDeploymentMutator) GVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    "cluster.x-k8s.io",
		Version:  "v1beta1",
		Resource: "machinedeployments/scale",
	}
}

// Operations returns list of operations handled by this mutator.
func (m *MachineDeploymentMutator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
		admissionregistrationv1.Update,
	}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (m *MachineDeploymentMutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.MutatingWebhook {
	mutatingWebhook := admission.NewDefaultMutatingWebhook(m, clientConfig, admissionregistrationv1.NamespacedScope, m.Operations())
	mutatingWebhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNoneOnDryRun)
	return []admissionregistrationv1.MutatingWebhook{*mutatingWebhook}
}

// Admit is the entrypoint for the mutator. Admit will return an error if it unable to process the request.
func (m *MachineDeploymentMutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if request.DryRun != nil && *request.DryRun {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}

	listTrace := trace.New("machineDeploymentScale Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	// Handle Scale object instead of MachineDeployment
	scale, err := m.getScaleFromRequest(request)
	if err != nil {
		return nil, err
	}

	// Look up MachineDeployment from cache using scale object name
	machineDeployment, err := m.MachineDeploymentCache.Get(scale.Namespace, scale.Name)
	if err != nil {
		// If MachineDeployment doesn't exist, return admitted (not error)
		if apierrors.IsNotFound(err) {
			logrus.Debugf("MachineDeployment %s/%s not found, admitting scale operation", scale.Namespace, scale.Name)
			return &admissionv1.AdmissionResponse{
				Allowed: true,
			}, nil
		}
		// For other errors, return error
		return nil, err
	}

	// If MachineDeployment exists, process it through sync pool replicas
	_, err = m.syncMachinePoolReplicas(machineDeployment, scale)
	if err != nil {
		logrus.Errorf("Failed to sync machine pool replicas for MachineDeployment %s/%s: %v",
			machineDeployment.Namespace, machineDeployment.Name, err)
		return admission.ResponseBadRequest(err.Error()), nil
	}

	response := &admissionv1.AdmissionResponse{
		Allowed: true,
	}

	return response, nil
}

// getScaleFromRequest extracts a Scale object from the admission request
func (m *MachineDeploymentMutator) getScaleFromRequest(request *admission.Request) (*autoscalingv1.Scale, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	scale := &autoscalingv1.Scale{}
	err := json.Unmarshal(request.Object.Raw, scale)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal scale object: %w", err)
	}

	return scale, nil
}

func (m *MachineDeploymentMutator) syncMachinePoolReplicas(md *capi.MachineDeployment, scale *autoscalingv1.Scale) (*capi.MachineDeployment, error) {
	if md == nil || md.DeletionTimestamp != nil {
		return md, nil
	}

	clusterName := md.Spec.Template.ObjectMeta.Labels[capi.ClusterNameLabel]
	if clusterName == "" {
		logrus.Debugf("MachineDeployment %s/%s has no cluster name label, skipping", md.Namespace, md.Name)
		return md, nil
	}

	machinePoolName := md.Spec.Template.ObjectMeta.Labels["rke.cattle.io/rke-machine-pool-name"]
	if machinePoolName == "" {
		logrus.Debugf("MachineDeployment %s/%s has no machine pool name label, skipping", md.Namespace, md.Name)
		return md, nil
	}

	// Get provisioning cluster directly (no need for CAPI cluster lookup)
	logrus.Debugf("Getting provisioning cluster %s/%s", md.Namespace, clusterName)
	cluster, err := m.ProvisioningClusterCache.Get(md.Namespace, clusterName)
	if err != nil {
		return nil, err
	}

	if cluster.Spec.RKEConfig == nil || cluster.Spec.RKEConfig.MachinePools == nil || len(cluster.Spec.RKEConfig.MachinePools) == 0 {
		return md, nil
	}

	needUpdate := false
	machinePoolFound := false
	cluster = cluster.DeepCopy()
	for i := range cluster.Spec.RKEConfig.MachinePools {
		if !(cluster.Spec.RKEConfig.MachinePools[i].Name == machinePoolName) {
			continue
		}

		machinePoolFound = true
		if cluster.Spec.RKEConfig.MachinePools[i].Quantity == nil || md.Spec.Replicas == nil {
			continue
		}

		logrus.Debugf("Found matching machine pool %s", machinePoolName)
		if *cluster.Spec.RKEConfig.MachinePools[i].Quantity != scale.Spec.Replicas {
			logrus.Infof("Updating cluster %s/%s machine pool %s quantity from %d to %d",
				cluster.Namespace, cluster.Name, machinePoolName,
				*cluster.Spec.RKEConfig.MachinePools[i].Quantity, scale.Spec.Replicas)
			*cluster.Spec.RKEConfig.MachinePools[i].Quantity = scale.Spec.Replicas
			needUpdate = true
		}
		break // Found the matching pool, no need to continue searching
	}

	if !machinePoolFound {
		logrus.Debugf("Machine pool %s not found in cluster %s/%s, skipping sync", machinePoolName, cluster.Namespace, cluster.Name)
		return md, nil
	}

	if needUpdate {
		logrus.Debugf("Updating cluster %s/%s", cluster.Namespace, cluster.Name)
		err := wait.ExponentialBackoff(retry.DefaultBackoff, func() (done bool, err error) {
			_, err = m.ProvisioningClusterClient.Update(cluster)
			if err != nil {
				return false, nil
			}
			return true, nil
		})
		if err != nil {
			logrus.Warnf("Failed to update cluster %s/%s machine pool %s to match machineDeployment: %v",
				cluster.Namespace, cluster.Name, machinePoolName, err)
			return nil, err
		}

		logrus.Debugf("Successfully updated cluster %s/%s", cluster.Namespace, cluster.Name)
	}

	return md, nil
}
