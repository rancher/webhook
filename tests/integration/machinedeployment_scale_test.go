package integration_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	provisioningv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
)

// GVK constants for CAPI types
var (
	capiClusterGVK = schema.GroupVersion{
		Group:   "cluster.x-k8s.io",
		Version: "v1beta1",
	}.WithKind("Cluster")
	capiMachineDeploymentGVK = schema.GroupVersion{
		Group:   "cluster.x-k8s.io",
		Version: "v1beta1",
	}.WithKind("MachineDeployment")
)

// GVK constants for Provisioning types
var (
	provisioningClusterGVK = schema.GroupVersion{
		Group:   "provisioning.cattle.io",
		Version: "v1",
	}.WithKind("Cluster")
)

// TestMachineDeploymentScaling tests various scaling scenarios for MachineDeployments.
// Each test case verifies that scaling a MachineDeployment updates the corresponding
// MachinePool quantity in the Provisioning Cluster.
func (m *IntegrationSuite) TestMachineDeploymentScaling() {
	// skipping these for now until we have the CAPI CRDs as part of CI
	if os.Getenv("TEST_MACHINE_DEPLOYMENTS_SCALE") == "" {
		m.T().Skip()
	}

	testCases := []struct {
		name            string
		initialReplicas int32
		targetReplicas  int32
	}{
		{"scale-up", 2, 5},
		{"scale-down", 5, 2},
		{"scale-to-zero", 3, 0},
	}

	for _, tc := range testCases {
		m.T().Run(tc.name, func(t *testing.T) {
			m.testMachineDeploymentScaling(t, tc.name, tc.initialReplicas, tc.targetReplicas)
		})
	}
}

// testMachineDeploymentScaling is a helper function for testing MachineDeployment scaling scenarios.
func (m *IntegrationSuite) testMachineDeploymentScaling(t *testing.T, testSuffix string, initialReplicas, targetReplicas int32) {
	// Define unique names for this test
	provClusterName := "test-provisioning-cluster-" + testSuffix
	capiClusterName := "test-capi-cluster-" + testSuffix
	machineDeploymentName := "test-machine-deployment-" + testSuffix
	machinePoolName := "test-machine-pool-" + testSuffix

	provClient, err := m.clientFactory.ForKind(provisioningClusterGVK)
	require.NoError(t, err, "Failed to create client for Provisioning Cluster")

	// Step 1: Create the Provisioning Cluster with a MachinePool
	provCluster := &provisioningv1.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      provClusterName,
			Namespace: m.testnamespace,
		},
		Spec: provisioningv1.ClusterSpec{
			RKEConfig: &provisioningv1.RKEConfig{
				MachinePools: []provisioningv1.RKEMachinePool{
					{
						Name:       machinePoolName,
						Quantity:   Ptr(initialReplicas),
						NodeConfig: &corev1.ObjectReference{Name: "default"},
					},
				},
			},
			KubernetesVersion: "v1.34.1+rke2r1",
		},
	}
	m.createObj(provCluster, provisioningClusterGVK)
	t.Cleanup(func() {
		m.deleteObj(provCluster, provisioningClusterGVK)
	})

	err = provClient.Get(t.Context(), provCluster.Namespace, provCluster.Name, provCluster, v1.GetOptions{})
	m.Nil(err)

	// Step 2: Create the CAPI Cluster
	capiCluster := &capi.Cluster{
		TypeMeta: v1.TypeMeta{
			APIVersion: "cluster.x-k8s.io/v1beta1",
			Kind:       "Cluster",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      capiClusterName,
			Namespace: m.testnamespace,
			OwnerReferences: []metav1.OwnerReference{{
				APIVersion: "provisioning.cattle.io/v1",
				Kind:       "Cluster",
				Name:       provClusterName,
				UID:        provCluster.UID,
			}},
		},
	}
	m.createObj(capiCluster, capiClusterGVK)
	t.Cleanup(func() {
		m.deleteObj(capiCluster, capiClusterGVK)
	})

	// Step 3: Create the MachineDeployment with labels pointing to CAPI Cluster and MachinePool
	machineDeployment := &capi.MachineDeployment{
		TypeMeta: v1.TypeMeta{
			APIVersion: "cluster.x-k8s.io/v1beta1",
			Kind:       "MachineDeployment",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      machineDeploymentName,
			Namespace: m.testnamespace,
		},
		Spec: capi.MachineDeploymentSpec{
			ClusterName: capiClusterName,
			Replicas:    Ptr(initialReplicas),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						capi.ClusterNameLabel:                 capiClusterName,
						"rke.cattle.io/rke-machine-pool-name": machinePoolName,
					},
				},
				Spec: capi.MachineSpec{
					ClusterName: capiClusterName,
					Bootstrap: capi.Bootstrap{
						ConfigRef: &corev1.ObjectReference{
							Name: "bootstrap-secret",
						},
					},
					InfrastructureRef: corev1.ObjectReference{
						Name: "infra-machine",
					},
				},
			},
		},
	}
	m.createObj(machineDeployment, capiMachineDeploymentGVK)
	t.Cleanup(func() {
		m.deleteObj(machineDeployment, capiMachineDeploymentGVK)
	})

	// Step 4: Scale the MachineDeployment by calling the scale subresource
	// This triggers the webhook which updates the Provisioning Cluster's MachinePool quantity
	client, err := m.clientFactory.ForKind(capiMachineDeploymentGVK)
	require.NoError(t, err, "Failed to create client for MachineDeployment")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	// Create a scale object with the target replicas
	scaleObj := map[string]any{
		"spec": map[string]any{
			"replicas": targetReplicas,
		},
	}
	scaleData, err := json.Marshal(scaleObj)
	require.NoError(t, err, "Failed to marshal scale object")

	err = client.Patch(ctx, m.testnamespace, machineDeploymentName, types.MergePatchType, scaleData, nil, v1.PatchOptions{}, "scale")
	require.NoError(t, err, "Failed to scale MachineDeployment after retries")

	// Step 5: Verify the MachinePool quantity in Provisioning Cluster is updated
	var updatedProvCluster provisioningv1.Cluster
	err = provClient.Get(ctx, m.testnamespace, provClusterName, &updatedProvCluster, v1.GetOptions{})
	require.NoError(t, err, "Failed to get Provisioning Cluster")

	// Find the machine pool and verify its quantity
	found := false
	for i := range updatedProvCluster.Spec.RKEConfig.MachinePools {
		pool := &updatedProvCluster.Spec.RKEConfig.MachinePools[i]
		if pool.Name == machinePoolName {
			found = true
			require.NotNil(t, pool.Quantity, "MachinePool quantity should not be nil after scale operation")
			assert.Equal(t, targetReplicas, *pool.Quantity, "MachinePool quantity should match scaled replicas")
			break
		}
	}
	assert.True(t, found, "MachinePool %s should exist in Provisioning Cluster", machinePoolName)
}

// TestMachineDeploymentScalingWithoutProvisioningCluster tests that scaling a MachineDeployment
// is admitted when the CAPI Cluster is not attached to a Provisioning Cluster.
// In this scenario, only CAPI resources are created (no Rancher Provisioning Cluster),
// and the scale operation should be allowed without updating any MachinePool.
func (m *IntegrationSuite) TestMachineDeploymentScalingWithoutProvisioningCluster() {
	// skipping these for now until we have the CAPI CRDs as part of CI
	if os.Getenv("TEST_MACHINE_DEPLOYMENTS_SCALE") == "" {
		m.T().Skip()
	}

	testCases := []struct {
		name            string
		initialReplicas int32
		targetReplicas  int32
	}{
		{"scale-up-unattached", 2, 5},
		{"scale-down-unattached", 5, 2},
		{"scale-to-zero-unattached", 3, 0},
	}

	for _, tc := range testCases {
		m.T().Run(tc.name, func(t *testing.T) {
			m.testMachineDeploymentScalingWithoutProvisioningCluster(t, tc.name, tc.initialReplicas, tc.targetReplicas)
		})
	}
}

// testMachineDeploymentScalingWithoutProvisioningCluster is a helper function for testing
// MachineDeployment scaling when the CAPI Cluster is not attached to a Provisioning Cluster.
func (m *IntegrationSuite) testMachineDeploymentScalingWithoutProvisioningCluster(t *testing.T, testSuffix string, initialReplicas, targetReplicas int32) {
	// Define unique names for this test
	capiClusterName := "test-capi-cluster-unattached-" + testSuffix
	machineDeploymentName := "test-machine-deployment-unattached-" + testSuffix

	// Step 1: Create the CAPI Cluster WITHOUT an owner reference to a Provisioning Cluster
	capiCluster := &capi.Cluster{
		TypeMeta: v1.TypeMeta{
			APIVersion: "cluster.x-k8s.io/v1beta1",
			Kind:       "Cluster",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      capiClusterName,
			Namespace: m.testnamespace,
			// Note: No OwnerReference to a Provisioning Cluster
		},
	}
	m.createObj(capiCluster, capiClusterGVK)
	t.Cleanup(func() {
		m.deleteObj(capiCluster, capiClusterGVK)
	})

	// Step 2: Create the MachineDeployment with labels pointing to CAPI Cluster
	// Note: No machine pool name label, so no MachinePool update will be attempted
	machineDeployment := &capi.MachineDeployment{
		TypeMeta: v1.TypeMeta{
			APIVersion: "cluster.x-k8s.io/v1beta1",
			Kind:       "MachineDeployment",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      machineDeploymentName,
			Namespace: m.testnamespace,
		},
		Spec: capi.MachineDeploymentSpec{
			ClusterName: capiClusterName,
			Replicas:    Ptr(initialReplicas),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						capi.ClusterNameLabel: capiClusterName,
						// Note: No "rke.cattle.io/rke-machine-pool-name" label
					},
				},
				Spec: capi.MachineSpec{
					ClusterName: capiClusterName,
					Bootstrap: capi.Bootstrap{
						ConfigRef: &corev1.ObjectReference{
							Name: "bootstrap-secret",
						},
					},
					InfrastructureRef: corev1.ObjectReference{
						Name: "infra-machine",
					},
				},
			},
		},
	}
	m.createObj(machineDeployment, capiMachineDeploymentGVK)
	t.Cleanup(func() {
		m.deleteObj(machineDeployment, capiMachineDeploymentGVK)
	})

	// Step 3: Scale the MachineDeployment by calling the scale subresource
	// This triggers the webhook which should admit the request since there's no Provisioning Cluster attached
	client, err := m.clientFactory.ForKind(capiMachineDeploymentGVK)
	require.NoError(t, err, "Failed to create client for MachineDeployment")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
	defer cancel()

	// Create a scale object with the target replicas
	scaleObj := map[string]any{
		"spec": map[string]any{
			"replicas": targetReplicas,
		},
	}
	scaleData, err := json.Marshal(scaleObj)
	require.NoError(t, err, "Failed to marshal scale object")

	// The scale operation should succeed because the webhook admits the request
	// when there's no Provisioning Cluster attached
	err = client.Patch(ctx, m.testnamespace, machineDeploymentName, types.MergePatchType, scaleData, nil, v1.PatchOptions{}, "scale")
	require.NoError(t, err, "Failed to scale MachineDeployment - the request should be admitted when provisioning cluster is not attached")

	// Step 4: Verify the MachineDeployment was scaled
	var updatedMD capi.MachineDeployment
	err = client.Get(ctx, m.testnamespace, machineDeploymentName, &updatedMD, v1.GetOptions{})
	require.NoError(t, err, "Failed to get MachineDeployment")
	assert.Equal(t, targetReplicas, *updatedMD.Spec.Replicas, "MachineDeployment replicas should match scaled value")
}
