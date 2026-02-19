package machinedeployment

import (
	"encoding/json"
	"fmt"

	provv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	provcontrollers "github.com/rancher/webhook/pkg/generated/controllers/provisioning.cattle.io/v1"
	scaling "github.com/rancher/webhook/pkg/generated/objects/autoscaling/v1"
	"github.com/sirupsen/logrus"
	jsonpatch "gopkg.in/evanphx/json-patch.v5"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
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

type dynamicGetter interface {
	Get(gvk schema.GroupVersionKind, namespace, name string) (runtime.Object, error)
}

// ReplicaValidator implements admission.ValidatingAdmissionWebhook.
type ReplicaValidator struct {
	// Provisioning cluster cache for retrieving provisioning Cluster objects
	clusterCache provcontrollers.ClusterCache
	// Provisioning cluster client for updating provisioning Cluster objects
	clusterClient provcontrollers.ClusterClient
	// dynamicGetter to fetch resources that we might not have the CRDs for
	dynamic dynamicGetter
}

// NewValidator returns a new ReplicaValidator populated by the caches and clients passed in.
func NewValidator(clusterCache provcontrollers.ClusterCache, clusterClient provcontrollers.ClusterClient,
	dynamic dynamicGetter) *ReplicaValidator {
	return &ReplicaValidator{
		clusterCache:  clusterCache,
		clusterClient: clusterClient,
		dynamic:       dynamic,
	}
}

// GVK constants for dynamic getter
var (
	machineDeploymentGVK = schema.GroupVersion{
		Group:   "cluster.x-k8s.io",
		Version: "v1beta1",
	}.WithKind("MachineDeployment")
	capiClusterGVK = schema.GroupVersion{
		Group:   "cluster.x-k8s.io",
		Version: "v1beta1",
	}.WithKind("Cluster")
)

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
		logrus.Debugf("DryRun request detected, admitting immediately")
		return admission.ResponseAllowed(), nil
	}

	listTrace := trace.New("machineDeploymentScale Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	scale, err := scaling.ScaleFromRequest(&request.AdmissionRequest)
	if err != nil {
		return admission.ResponseBadRequest(err.Error()), nil
	}

	machineDeployment, err := v.getMachineDeployment(scale.Namespace, scale.Name)
	if err != nil {
		logrus.Debugf("MachineDeployment %s/%s not found, admitting scale operation", scale.Namespace, scale.Name)
		return admission.ResponseAllowed(), nil
	}

	// If MachineDeployment exists, process it through sync pool replicas
	err = v.reconcileMachinePoolReplicas(machineDeployment, scale.Spec.Replicas)
	if err == nil || apierrors.IsNotFound(err) {
		// prov/CAPI cluster do not exist or the machinedeployment isn't managed by rancher
		return admission.ResponseAllowed(), nil
	}

	logrus.Errorf("Failed to sync machine pool replicas for MachineDeployment %s/%s: %v", machineDeployment.Namespace, machineDeployment.Name, err)
	return admission.ResponseBadRequest(err.Error()), err
}

// reconcileMachinePoolReplicas performs the lookup and update of machine pool replicas.
// Uses Kubernetes built-in retry utilities for conflict/timeout handling.
//
// Flow:
// In a retry loop:
//  1. Looks up the CAPI cluster
//  2. Finds the Rancher Provisioning Cluster through owner references on the CAPI Cluster
//  3. Updates the machine pool's quantity to match the target replicas
//  4. Updates the cluster object with the new machinepool in k8s
//
// Returns:
// - nil if update was successful
// - error if cluster or machine pool not found, or update fails after retries
func (v *ReplicaValidator) reconcileMachinePoolReplicas(md *capi.MachineDeployment, targetReplicas int32) error {
	cluster, err := v.fetchProvisioningCluster(md)
	if err != nil {
		return err
	}

	if cluster.Spec.RKEConfig == nil || cluster.Spec.RKEConfig.MachinePools == nil || len(cluster.Spec.RKEConfig.MachinePools) == 0 {
		logrus.Debugf("Provisioning cluster %s/%s does not have required RKEConfig or MachinePools", cluster.Namespace, cluster.Name)
		return nil
	}

	// Find and update the matching machine pool
	updatedCluster, needUpdate := v.setMachinePoolQuantity(md, cluster, targetReplicas)
	if !needUpdate {
		return nil
	}

	originalCluster, _ := json.Marshal(cluster)
	newCluster, _ := json.Marshal(updatedCluster)
	patch, err := jsonpatch.CreateMergePatch(originalCluster, newCluster)
	if err != nil {
		return fmt.Errorf("failed to generate json patch: %v", err)
	}

	_, err = v.clusterClient.Patch(cluster.Namespace, cluster.Name, types.MergePatchType, patch, "")
	return err
}

// setMachinePoolQuantity finds the machine pool by name and updates its quantity
// if it differs from the target replicas.
//
// Returns:
// - (modifiedCluster, true) if update was needed and performed
// - (cluster, false) if no update was needed or pool not found
func (v *ReplicaValidator) setMachinePoolQuantity(md *capi.MachineDeployment, cluster *provv1.Cluster, targetReplicas int32) (*provv1.Cluster, bool) {
	machinePoolName := md.Spec.Template.ObjectMeta.Labels[machinePoolNameLabel]
	if machinePoolName == "" {
		return nil, false
	}

	cluster = cluster.DeepCopy()
	for i := range cluster.Spec.RKEConfig.MachinePools {
		pool := &cluster.Spec.RKEConfig.MachinePools[i]
		if pool.Name != machinePoolName {
			continue
		}

		// If quantity is nil and targetReplicas is zero, or quantity is non-nil and already
		// equals targetReplicas, no update is needed.
		if pool.Quantity == nil && targetReplicas == 0 {
			return cluster, false
		} else if *pool.Quantity == targetReplicas {
			return cluster, false
		}

		logrus.Debugf("Updating cluster %s/%s machine pool %s quantity from %d to %d", cluster.Namespace, cluster.Name, machinePoolName, *pool.Quantity, targetReplicas)
		if pool.Quantity == nil {
			pool.Quantity = new(int32)
		}
		*pool.Quantity = targetReplicas
		return cluster, true
	}

	logrus.Debugf("Machine pool %s not found in cluster %s/%s, skipping sync", machinePoolName, cluster.Namespace, cluster.Name)
	return cluster, false
}

// getMachineDeployment retrieves a MachineDeployment object using the dynamic client,
// handling both typed and unstructured objects.
//
// Returns:
// - (*capi.MachineDeployment, nil) if the MachineDeployment is found
// - (nil, error) if the lookup fails or conversion fails
func (v *ReplicaValidator) getMachineDeployment(namespace, name string) (*capi.MachineDeployment, error) {
	logrus.Debugf("Getting MachineDeployment %s/%s", namespace, name)
	return fetchGenericObject(v.dynamic, namespace, name, machineDeploymentGVK, &capi.MachineDeployment{})
}

// fetchCAPICluster retrieves the CAPI Cluster associated with the MachineDeployment
// by extracting the cluster name from the MachineDeployment's labels.
//
// Returns:
// - (*capi.Cluster, nil) if the CAPI cluster is found
// - (nil, error) if the cluster is not found or lookup fails
func (v *ReplicaValidator) fetchCAPICluster(md *capi.MachineDeployment) (*capi.Cluster, error) {
	clusterName := md.Spec.Template.ObjectMeta.Labels[capi.ClusterNameLabel]

	if clusterName == "" {
		logrus.Debugf("MachineDeployment %s/%s has no CAPI cluster name label", md.Namespace, md.Name)
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: "cluster.x-k8s.io", Resource: "clusters"}, "")
	}

	logrus.Debugf("Getting CAPI cluster %s/%s", md.Namespace, clusterName)
	return fetchGenericObject(v.dynamic, md.Namespace, clusterName, capiClusterGVK, &capi.Cluster{})
}

// fetchProvisioningCluster locates the Rancher Provisioning Cluster by checking
// owner references on the CAPI Cluster and performing a lookup.
//
// Returns:
// - (*provv1.Cluster, nil) if the provisioning cluster is found
// - (nil, error) if the provisioning cluster is not found or lookup fails
func (v *ReplicaValidator) fetchProvisioningCluster(md *capi.MachineDeployment) (*provv1.Cluster, error) {
	capiCluster, err := v.fetchCAPICluster(md)
	if err != nil {
		return nil, err
	}

	for _, owner := range capiCluster.OwnerReferences {
		if owner.APIVersion == provisioningAPIVersion && owner.Kind == provisioningClusterKind {
			logrus.Debugf("Getting provisioning cluster %s/%s", capiCluster.Namespace, owner.Name)
			return v.clusterCache.Get(capiCluster.Namespace, owner.Name)
		}
	}

	logrus.Debugf("CAPI cluster %s/%s has no provisioning.cattle.io/v1 Cluster owner reference", capiCluster.Namespace, capiCluster.Name)
	return nil, apierrors.NewNotFound(schema.GroupResource{Group: "provisioning.cattle.io", Resource: "clusters"}, fmt.Sprintf("%s/%s", capiCluster.Namespace, capiCluster.Name))
}

// fetchGenericObject retrieves a Kubernetes object by its GVK, namespace, and name,
// then converts it to the specified type T.
//
// This function handles two scenarios:
// 1. The object is already of type T (direct type assertion)
// 2. The object is an unstructured.Unstructured (conversion via FromUnstructured)
//
// Parameters:
//   - d: dynamicGetter interface for fetching objects dynamically
//   - namespace: Kubernetes namespace of the object
//   - name: Name of the object
//   - gvk: GroupVersionKind identifying the resource type
//   - out: Zero value of type T used for type conversion
//
// Returns:
//   - (T, nil): Successfully retrieved and converted object
//   - (*new(T), error): Failed to fetch or convert the object
func fetchGenericObject[T any](d dynamicGetter, namespace, name string, gvk schema.GroupVersionKind, out T) (T, error) {
	obj, err := d.Get(gvk, namespace, name)
	if err != nil {
		return *new(T), err
	}

	typedObj, ok := obj.(T)
	if ok {
		return typedObj, nil
	}

	unstr, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return *new(T), fmt.Errorf("type conversion failed for %s/%s: %T", namespace, name, out)
	}

	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstr.Object, out); err != nil {
		return *new(T), fmt.Errorf("failed to convert object: %w", err)
	}

	return out, nil
}
