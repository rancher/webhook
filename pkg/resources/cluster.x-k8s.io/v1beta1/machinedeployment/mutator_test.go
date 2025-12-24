package machinedeployment

import (
	"context"
	"encoding/json"
	"testing"

	v2prov "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
)

type MachineDeploymentMutatorSuite struct {
	suite.Suite
}

func TestMachineDeploymentMutator(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(MachineDeploymentMutatorSuite))
}

func (suite *MachineDeploymentMutatorSuite) TestHappyPath() {
	ctrl := gomock.NewController(suite.T())

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)

	// Set up expected calls for MachineDeployment cache lookup
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{},
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: func() *int32 { v := int32(3); return &v }(),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						"cluster.x-k8s.io/cluster-name":     "test-cluster",
						"rke.cattle.io/rke-machine-pool-name": "test-machine-pool",
					},
				},
			},
		},
	}, nil)

	// Set up expected call for provisioning cluster cache lookup
	mockProvClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&v2prov.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
		},
		Spec: v2prov.ClusterSpec{
			RKEConfig: &v2prov.RKEConfig{
				MachinePools: []v2prov.RKEMachinePool{
					{
						Name:     "test-machine-pool",
						Quantity: func() *int32 { v := int32(2); return &v }(),
					},
				},
			},
		},
	}, nil)

	// Create mock client and set up expected call for provisioning cluster update
	mockProvClusterClient := fake.NewMockControllerInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)
	mockProvClusterClient.EXPECT().Update(gomock.Any()).Return(&v2prov.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
		},
		Spec: v2prov.ClusterSpec{
			RKEConfig: &v2prov.RKEConfig{
				MachinePools: []v2prov.RKEMachinePool{
					{
						Name:     "test-machine-pool",
						Quantity: func() *int32 { v := int32(3); return &v }(),
					},
				},
			},
		},
	}, nil)

	// Create mutator with mock caches and client
	mutator := NewMachineDeploymentMutator(mockMachineDeploymentCache, mockProvClusterCache, mockProvClusterClient)

	// Create test Scale object with 3 replicas (should trigger update)
	scale := createTestScale("test-namespace", "test-md", 3)

	resp, err := mutator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request was denied")
}

func (suite *MachineDeploymentMutatorSuite) TestClustersNotFound() {
	ctrl := gomock.NewController(suite.T())

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)

	// Set up expected calls to return not found errors
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(nil, apierrors.NewNotFound(schema.GroupResource{Group: "cluster.x-k8s.io", Resource: "machinedeployments"}, "test-md"))

	// Create mutator with mock caches
	mutator := NewMachineDeploymentMutator(mockMachineDeploymentCache, mockProvClusterCache, nil)

	// Create test Scale object
	scale := createTestScale("test-namespace", "test-md", 3)

	resp, err := mutator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	// Should return admitted (not error) when MachineDeployment is not found
	suite.Nil(err)
	suite.True(resp.Allowed, "admission request should be admitted when MachineDeployment not found")
}

func (suite *MachineDeploymentMutatorSuite) TestMachinePoolNotFound() {
	ctrl := gomock.NewController(suite.T())

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)

	// Set up expected calls
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{},
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: func() *int32 { v := int32(3); return &v }(),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						"cluster.x-k8s.io/cluster-name":     "test-cluster",
						"rke.cattle.io/rke-machine-pool-name": "non-existent-pool",
					},
				},
			},
		},
	}, nil)

	mockProvClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&v2prov.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
		},
		Spec: v2prov.ClusterSpec{
			RKEConfig: &v2prov.RKEConfig{
				MachinePools: []v2prov.RKEMachinePool{
					{
						Name:     "different-machine-pool",
						Quantity: func() *int32 { v := int32(2); return &v }(),
					},
				},
			},
		},
	}, nil)

	// Create mutator with mock caches
	mutator := NewMachineDeploymentMutator(mockMachineDeploymentCache, mockProvClusterCache, nil)

	// Create test Scale object with non-existent machine pool
	scale := createTestScale("test-namespace", "test-md", 3)

	resp, err := mutator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	// Should return admitted (not error) when machine pool is not found
	suite.Nil(err)
	suite.True(resp.Allowed, "admission request should be admitted when machine pool not found")
}

func (suite *MachineDeploymentMutatorSuite) TestMissingLabels() {
	ctrl := gomock.NewController(suite.T())

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)

	// Set up expected call for MachineDeployment cache lookup (will be called but provisioning cluster won't be)
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{}, // No cluster name or machine pool labels
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: func() *int32 { v := int32(3); return &v }(),
		},
	}, nil)

	// Create mutator with mock caches
	mutator := NewMachineDeploymentMutator(mockMachineDeploymentCache, mockProvClusterCache, nil)

	// Create test Scale object
	scale := createTestScale("test-namespace", "test-md", 3)

	resp, err := mutator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request was denied")
}

func (suite *MachineDeploymentMutatorSuite) TestReplicasAlreadyMatch() {
	ctrl := gomock.NewController(suite.T())

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)

	// Set up expected calls
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{},
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: func() *int32 { v := int32(3); return &v }(),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						"cluster.x-k8s.io/cluster-name":     "test-cluster",
						"rke.cattle.io/rke-machine-pool-name": "test-machine-pool",
					},
				},
			},
		},
	}, nil)

	mockProvClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&v2prov.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
		},
		Spec: v2prov.ClusterSpec{
			RKEConfig: &v2prov.RKEConfig{
				MachinePools: []v2prov.RKEMachinePool{
					{
						Name:     "test-machine-pool",
						Quantity: func() *int32 { v := int32(3); return &v }(), // Same as MachineDeployment replicas
					},
				},
			},
		},
	}, nil)

	// Create mock client
	mockProvClusterClient := fake.NewMockControllerInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Create mutator with mock caches and client
	mutator := NewMachineDeploymentMutator(mockMachineDeploymentCache, mockProvClusterCache, mockProvClusterClient)

	// Create test Scale object with 3 replicas (matches machine pool)
	scale := createTestScale("test-namespace", "test-md", 3)
	oldScale := createTestScale("test-namespace", "test-md", 3)

	resp, err := mutator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Update,
			Object:    runtime.RawExtension{Raw: scale},
			OldObject: runtime.RawExtension{Raw: oldScale},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request was denied")
}

func (suite *MachineDeploymentMutatorSuite) TestDryRun() {
	ctrl := gomock.NewController(suite.T())

	// Create mock caches (should not be called in dry run)
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)

	// Create mutator with mock caches
	mutator := NewMachineDeploymentMutator(mockMachineDeploymentCache, mockProvClusterCache, nil)

	// Create test Scale object
	scale := createTestScale("test-namespace", "test-md", 3)

	// Set dry run to true
	dryRun := true
	resp, err := mutator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
			DryRun:    &dryRun,
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request was denied")
}

func (suite *MachineDeploymentMutatorSuite) TestUpdateOperation() {
	ctrl := gomock.NewController(suite.T())

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)

	// Set up expected calls
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{},
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: func() *int32 { v := int32(5); return &v }(),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						"cluster.x-k8s.io/cluster-name":     "test-cluster",
						"rke.cattle.io/rke-machine-pool-name": "test-machine-pool",
					},
				},
			},
		},
	}, nil)

	mockProvClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&v2prov.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
		},
		Spec: v2prov.ClusterSpec{
			RKEConfig: &v2prov.RKEConfig{
				MachinePools: []v2prov.RKEMachinePool{
					{
						Name:     "test-machine-pool",
						Quantity: func() *int32 { v := int32(2); return &v }(),
					},
				},
			},
		},
	}, nil)

	// Create mock client
	mockProvClusterClient := fake.NewMockControllerInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)
	updatedCluster := &v2prov.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
		},
		Spec: v2prov.ClusterSpec{
			RKEConfig: &v2prov.RKEConfig{
				MachinePools: []v2prov.RKEMachinePool{
					{
						Name:     "test-machine-pool",
						Quantity: func() *int32 { v := int32(5); return &v }(), // Updated quantity
					},
				},
			},
		},
	}
	mockProvClusterClient.EXPECT().Update(gomock.Any()).Return(updatedCluster, nil)

	// Create mutator with mock caches and client
	mutator := NewMachineDeploymentMutator(mockMachineDeploymentCache, mockProvClusterCache, mockProvClusterClient)

	// Create test Scale object with 5 replicas (should trigger update)
	scale := createTestScale("test-namespace", "test-md", 5)
	oldScale := createTestScale("test-namespace", "test-md", 2)

	resp, err := mutator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Update,
			Object:    runtime.RawExtension{Raw: scale},
			OldObject: runtime.RawExtension{Raw: oldScale},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request was denied")
}

// Helper functions for creating test data

func createTestScale(namespace, name string, replicas int32) []byte {
	scale := autoscalingv1.Scale{
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Spec: autoscalingv1.ScaleSpec{
			Replicas: replicas,
		},
	}

	b, _ := json.Marshal(&scale)
	return b
}

func (suite *MachineDeploymentMutatorSuite) TestMachineDeploymentNotFound() {
	ctrl := gomock.NewController(suite.T())

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)

	// Set up expected call to return not found error
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "non-existent-md").Return(nil, apierrors.NewNotFound(schema.GroupResource{Group: "cluster.x-k8s.io", Resource: "machinedeployments"}, "non-existent-md"))

	// Create mutator with mock caches
	mutator := NewMachineDeploymentMutator(mockMachineDeploymentCache, mockProvClusterCache, nil)

	// Create test Scale object for non-existent MachineDeployment
	scale := createTestScale("test-namespace", "non-existent-md", 3)

	resp, err := mutator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	// Should return admitted (not error) when MachineDeployment doesn't exist
	suite.Nil(err)
	suite.True(resp.Allowed, "admission request should be admitted when MachineDeployment not found")
}
