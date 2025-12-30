package machinedeployment

import (
	provv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	capicontrollers "github.com/rancher/webhook/pkg/generated/controllers/cluster.x-k8s.io/v1beta1"
	provcontrollers "github.com/rancher/webhook/pkg/generated/controllers/provisioning.cattle.io/v1"
	scaling "github.com/rancher/webhook/pkg/generated/objects/autoscaling/v1"
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

// Label constants for MachineDeployment labels
const (
	machinePoolNameLabel = "rke.cattle.io/rke-machine-pool-name"
)

// Owner reference constants for provisioning cluster lookup
const (
	provisioningAPIVersion  = "provisioning.cattle.io/v1"
	provisioningClusterKind = "Cluster"
)

// ReplicaValidator implements admission.ValidatingAdmissionWebhook.
type ReplicaValidator struct {
	// MachineDeployment cache for retrieving MachineDeployment objects
	machineDeploymentCache capicontrollers.MachineDeploymentCache
	// CAPI cluster cache for retrieving CAPI Cluster objects
	capiClusterCache capicontrollers.ClusterCache
	// Provisioning cluster cache for retrieving provisioning Cluster objects
	clusterCache provcontrollers.ClusterCache
	// Provisioning cluster client for updating provisioning Cluster objects
	clusterClient provcontrollers.ClusterClient
}

// NewValidator returns a new ReplicaValidator populated by the caches and clients passed in.
func NewValidator(clusterCache provcontrollers.ClusterCache, clusterClient provcontrollers.ClusterClient,
	machineDeploymentCache capicontrollers.MachineDeploymentCache, capiClusterCache capicontrollers.ClusterCache) *ReplicaValidator {
	return &ReplicaValidator{
		clusterCache:           clusterCache,
		clusterClient:          clusterClient,
		machineDeploymentCache: machineDeploymentCache,
		capiClusterCache:       capiClusterCache,
	}
}

// GVR returns the GroupVersionKind for this Validating Webhook
func (v *ReplicaValidator) GVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    "cluster.x-k8s.io",
		Version:  "v1beta1",
		Resource: "machinedeployments/scale",
	}
}

// Operations returns list of operations handled by this validator.
func (v *ReplicaValidator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
		admissionregistrationv1.Update,
	}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *ReplicaValidator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	validatingWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope, v.Operations())
	validatingWebhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNoneOnDryRun)
	return []admissionregistrationv1.ValidatingWebhook{*validatingWebhook}
}

func (v *ReplicaValidator) Admitters() []admission.Admitter {
	return []admission.Admitter{v}
}

// Admit is the entrypoint for the validator. Admit will return an error if was unable to process the request.
func (v *ReplicaValidator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	// Early exit for dry-run requests
	if request.DryRun != nil && *request.DryRun {
		return admission.ResponseAllowed(), nil
	}

	listTrace := trace.New("machineDeploymentScale Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	scale, err := scaling.ScaleFromRequest(&request.AdmissionRequest)
	if err != nil {
		return admission.ResponseBadRequest(err.Error()), nil
	}

	machineDeployment, err := v.machineDeploymentCache.Get(scale.Namespace, scale.Name)
	if err != nil {
		// If MachineDeployment matching the scale request doesn't exist, return admitted (not error)
		// this is important because the scale subresource doesn't give a kind, just a label selector.
		logrus.Debugf("MachineDeployment %s/%s not found, admitting scale operation", scale.Namespace, scale.Name)
		return admission.ResponseAllowed(), nil
	}

	// If MachineDeployment exists, process it through sync pool replicas
	err = v.syncMachinePoolReplicas(machineDeployment, scale)
	if err != nil {
		logrus.Errorf("Failed to sync machine pool replicas for MachineDeployment %s/%s: %v",
			machineDeployment.Namespace, machineDeployment.Name, err)
		return admission.ResponseFailedEscalation(err.Error()), err
	}

	return admission.ResponseAllowed(), nil
}

// syncMachinePoolReplicas synchronizes the replica count between a MachineDeployment and its corresponding
// machine pool in the provisioning cluster. This method is called when a scale operation is performed
// on a MachineDeployment.
//
// Flow:
// 1. Validates the MachineDeployment exists and is not being deleted
// 2. Extracts the cluster name and machine pool name from MachineDeployment labels
// 3. Retrieves the CAPI Cluster object using the cluster name label
// 4. Finds the Rancher Provisioning Cluster by checking owner references on the CAPI Cluster
// 5. Locates the matching machine pool in the provisioning Cluster's RKEConfig
// 6. Compares the replica count from the scale request with the machine pool's quantity
// 7. If they differ, updates the machine pool's quantity to match the scale request
// 8. Persists the update to the provisioning Cluster using exponential backoff retry
//
// Returns:
// - nil if sync was successful or no update was needed
// - error if any lookup fails or the update operation fails
//
// Skips synchronization if:
// - Required labels (cluster name or machine pool name) are missing
// - Provisioning cluster, RKEConfig, or MachinePools are not configured
// - The specified machine pool is not found in the provisioning cluster
// - Replica quantities are nil (not set)
func (v *ReplicaValidator) syncMachinePoolReplicas(md *capi.MachineDeployment, scale *autoscalingv1.Scale) error {
	clusterName := md.Spec.Template.ObjectMeta.Labels[capi.ClusterNameLabel]
	if clusterName == "" {
		logrus.Debugf("MachineDeployment %s/%s has no cluster name label, skipping", md.Namespace, md.Name)
		return nil
	}

	machinePoolName := md.Spec.Template.ObjectMeta.Labels[machinePoolNameLabel]
	if machinePoolName == "" {
		logrus.Debugf("MachineDeployment %s/%s has no machine pool name label, skipping", md.Namespace, md.Name)
		return nil
	}

	logrus.Debugf("Getting CAPI cluster %s/%s", md.Namespace, clusterName)
	capiCluster, err := v.capiClusterCache.Get(md.Namespace, clusterName)
	if err != nil {
		return err
	}

	// Find the provisioning cluster through owner references
	cluster, err := v.findProvisioningClusterOwner(capiCluster)
	if err != nil || cluster != nil {
		logrus.Debugf("Provisioning cluster does not exist for CAPI cluster: %s/%s", capiCluster.Namespace, capiCluster.Name)
		return err
	}

	// Validate cluster has required configuration
	if cluster.Spec.RKEConfig == nil || cluster.Spec.RKEConfig.MachinePools == nil || len(cluster.Spec.RKEConfig.MachinePools) == 0 {
		logrus.Debugf("Provisioning cluster %s/%s does not have required RKEConfig or MachinePools, skipping sync", cluster.Namespace, cluster.Name)
		return nil
	}

	// Find and update the matching machine pool
	cluster, needUpdate, err := v.updateMachinePoolQuantity(cluster, machinePoolName, scale.Spec.Replicas)
	if err != nil {
		return err
	}

	if needUpdate {
		logrus.Debugf("Updating cluster %s/%s", cluster.Namespace, cluster.Name)
		err := wait.ExponentialBackoff(retry.DefaultBackoff, func() (done bool, err error) {
			_, err = v.clusterClient.Update(cluster)
			if err != nil {
				if apierrors.IsConflict(err) || apierrors.IsServerTimeout(err) {
					return false, nil
				}
				return false, err
			}
			return true, nil
		})
		if err != nil {
			logrus.Warnf("Failed to update cluster %s/%s machine pool %s to match machineDeployment: %v",
				cluster.Namespace, cluster.Name, machinePoolName, err)
			return err
		}

		logrus.Debugf("Successfully updated cluster %s/%s", cluster.Namespace, cluster.Name)
	}

	return nil
}

// findProvisioningClusterOwner locates the Rancher Provisioning Cluster by checking
// owner references on the CAPI Cluster.
//
// Returns:
// - *provv1.Cluster if found
// - error if not found or lookup fails
func (v *ReplicaValidator) findProvisioningClusterOwner(capiCluster *capi.Cluster) (*provv1.Cluster, error) {
	for _, owner := range capiCluster.OwnerReferences {
		if owner.APIVersion != provisioningAPIVersion || owner.Kind != provisioningClusterKind {
			continue
		}
		logrus.Debugf("Getting provisioning cluster %s/%s", capiCluster.Namespace, owner.Name)
		return v.clusterCache.Get(capiCluster.Namespace, owner.Name)
	}
	return nil, nil
}

// updateMachinePoolQuantity finds the machine pool by name and updates its quantity
// if it differs from the target replicas.
//
// Returns:
// - (modifiedCluster, true, nil) if update was needed and performed
// - (cluster, false, nil) if no update was needed
// - (nil, false, error) if machine pool not found or other error
func (v *ReplicaValidator) updateMachinePoolQuantity(cluster *provv1.Cluster, machinePoolName string, targetReplicas int32) (*provv1.Cluster, bool, error) {
	machinePoolFound := false
	cluster = cluster.DeepCopy()

	for i := range cluster.Spec.RKEConfig.MachinePools {
		if cluster.Spec.RKEConfig.MachinePools[i].Name != machinePoolName {
			continue
		}

		if cluster.Spec.RKEConfig.MachinePools[i].Quantity == nil {
			continue
		}

		machinePoolFound = true
		currentQuantity := *cluster.Spec.RKEConfig.MachinePools[i].Quantity

		if currentQuantity != targetReplicas {
			logrus.Infof("Updating cluster %s/%s machine pool %s quantity from %d to %d", cluster.Namespace, cluster.Name, machinePoolName, currentQuantity, targetReplicas)
			*cluster.Spec.RKEConfig.MachinePools[i].Quantity = targetReplicas

			return cluster, true, nil
		}

		break // Found the matching pool, no need to continue searching
	}

	if !machinePoolFound {
		logrus.Debugf("Machine pool %s not found in cluster %s/%s, skipping sync", machinePoolName, cluster.Namespace, cluster.Name)
	}

	return cluster, false, nil
}
