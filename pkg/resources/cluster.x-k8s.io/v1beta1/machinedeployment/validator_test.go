package machinedeployment

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	v2prov "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	capi "sigs.k8s.io/cluster-api/api/v1beta1"
)

type MachineDeploymentValidatorSuite struct {
	suite.Suite
}

func TestMachineDeploymentValidator(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(MachineDeploymentValidatorSuite))
}

func (suite *MachineDeploymentValidatorSuite) TestHappyPath() {
	ctrl := gomock.NewController(suite.T())
	defer ctrl.Finish()

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockCAPIClusterCache := fake.NewMockCacheInterface[*capi.Cluster](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)
	mockProvClusterClient := fake.NewMockClientInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Set up expected calls for MachineDeployment cache lookup
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{},
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: admission.Ptr(int32(3)),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						capi.ClusterNameLabel:                 "test-cluster",
						"rke.cattle.io/rke-machine-pool-name": "test-machine-pool",
					},
				},
			},
		},
	}, nil)

	// Set up expected call for CAPI cluster cache lookup
	mockCAPIClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&capi.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
			OwnerReferences: []v1.OwnerReference{
				{
					APIVersion: "provisioning.cattle.io/v1",
					Kind:       "Cluster",
					Name:       "test-cluster",
				},
			},
		},
		Spec: capi.ClusterSpec{
			InfrastructureRef: &corev1.ObjectReference{
				Name:      "test-cluster",
				Namespace: "test-namespace",
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
						Quantity: admission.Ptr(int32(2)),
					},
				},
			},
		},
	}, nil)

	// Set up expected call for provisioning cluster client update
	mockProvClusterClient.EXPECT().Update(gomock.Any()).Return(&v2prov.Cluster{}, nil)

	// Create validator with mock caches
	validator := NewValidator(mockProvClusterCache, mockProvClusterClient, mockMachineDeploymentCache, mockCAPIClusterCache)

	// Create test Scale object with 3 replicas (should trigger update)
	scale := createTestScale("test-namespace", "test-md", 3)

	resp, err := validator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request was denied")
}

func (suite *MachineDeploymentValidatorSuite) TestMachineDeploymentNotFoundAdmit() {
	ctrl := gomock.NewController(suite.T())
	defer ctrl.Finish()

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockCAPIClusterCache := fake.NewMockCacheInterface[*capi.Cluster](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)
	mockProvClusterClient := fake.NewMockClientInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Set up expected calls to return not found errors
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(nil, apierrors.NewNotFound(schema.GroupResource{Group: "cluster.x-k8s.io", Resource: "machinedeployments"}, "test-md"))

	// Create validator with mock clients
	validator := NewValidator(mockProvClusterCache, mockProvClusterClient, mockMachineDeploymentCache, mockCAPIClusterCache)

	// Create test Scale object
	scale := createTestScale("test-namespace", "test-md", 3)

	resp, err := validator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	// Should return admitted (not error) when MachineDeployment is not found
	suite.Nil(err)
	suite.True(resp.Allowed, "admission request should be admitted when MachineDeployment not found")
}

func (suite *MachineDeploymentValidatorSuite) TestMachinePoolNotFound() {
	ctrl := gomock.NewController(suite.T())
	defer ctrl.Finish()

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockCAPIClusterCache := fake.NewMockCacheInterface[*capi.Cluster](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)
	mockProvClusterClient := fake.NewMockClientInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Set up expected calls
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{},
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: admission.Ptr(int32(3)),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						capi.ClusterNameLabel:                 "test-cluster",
						"rke.cattle.io/rke-machine-pool-name": "non-existent-pool",
					},
				},
			},
		},
	}, nil)

	mockCAPIClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&capi.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
			OwnerReferences: []v1.OwnerReference{
				{
					APIVersion: "provisioning.cattle.io/v1",
					Kind:       "Cluster",
					Name:       "test-cluster",
				},
			},
		},
		Spec: capi.ClusterSpec{
			InfrastructureRef: &corev1.ObjectReference{
				Name:      "test-cluster",
				Namespace: "test-namespace",
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
						Name:     "different-machine-pool",
						Quantity: admission.Ptr(int32(2)),
					},
				},
			},
		},
	}, nil)

	// Create validator with mock clients
	validator := NewValidator(mockProvClusterCache, mockProvClusterClient, mockMachineDeploymentCache, mockCAPIClusterCache)

	// Create test Scale object with non-existent machine pool
	scale := createTestScale("test-namespace", "test-md", 3)

	resp, err := validator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	// Should return admitted (not error) when machine pool is not found
	suite.Nil(err)
	suite.True(resp.Allowed, "admission request should be admitted when machine pool not found")
}

func (suite *MachineDeploymentValidatorSuite) TestMissingLabels() {
	ctrl := gomock.NewController(suite.T())
	defer ctrl.Finish()

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockCAPIClusterCache := fake.NewMockCacheInterface[*capi.Cluster](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)
	mockProvClusterClient := fake.NewMockClientInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Set up expected call for MachineDeployment cache lookup (will be called but provisioning cluster won't be)
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{}, // No cluster name or machine pool labels
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: admission.Ptr(int32(3)),
		},
	}, nil)

	// Create validator with mock clients
	validator := NewValidator(mockProvClusterCache, mockProvClusterClient, mockMachineDeploymentCache, mockCAPIClusterCache)

	// Create test Scale object
	scale := createTestScale("test-namespace", "test-md", 3)

	resp, err := validator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request was denied")
}

func (suite *MachineDeploymentValidatorSuite) TestReplicasAlreadyMatch() {
	ctrl := gomock.NewController(suite.T())
	defer ctrl.Finish()

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockCAPIClusterCache := fake.NewMockCacheInterface[*capi.Cluster](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)
	mockProvClusterClient := fake.NewMockClientInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Set up expected calls
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{},
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: admission.Ptr(int32(3)),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						capi.ClusterNameLabel:                 "test-cluster",
						"rke.cattle.io/rke-machine-pool-name": "test-machine-pool",
					},
				},
			},
		},
	}, nil)

	mockCAPIClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&capi.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
			OwnerReferences: []v1.OwnerReference{
				{
					APIVersion: "provisioning.cattle.io/v1",
					Kind:       "Cluster",
					Name:       "test-cluster",
				},
			},
		},
		Spec: capi.ClusterSpec{
			InfrastructureRef: &corev1.ObjectReference{
				Name:      "test-cluster",
				Namespace: "test-namespace",
			},
		},
	}, nil)

	// Set up expected call for provisioning cluster cache lookup (called twice: initial + in retry loop)
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
						Quantity: admission.Ptr(int32(3)), // Same as MachineDeployment replicas
					},
				},
			},
		},
	}, nil)

	// Create validator with mock clients
	validator := NewValidator(mockProvClusterCache, mockProvClusterClient, mockMachineDeploymentCache, mockCAPIClusterCache)

	// Create test Scale object with 3 replicas (matches machine pool)
	scale := createTestScale("test-namespace", "test-md", 3)
	oldScale := createTestScale("test-namespace", "test-md", 3)

	resp, err := validator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Update,
			Object:    runtime.RawExtension{Raw: scale},
			OldObject: runtime.RawExtension{Raw: oldScale},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request was denied")
}

func (suite *MachineDeploymentValidatorSuite) TestDryRun() {
	ctrl := gomock.NewController(suite.T())
	defer ctrl.Finish()

	// Create mock caches (should not be called in dry run)
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockCAPIClusterCache := fake.NewMockCacheInterface[*capi.Cluster](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)
	mockProvClusterClient := fake.NewMockClientInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Create validator with mock clients
	validator := NewValidator(mockProvClusterCache, mockProvClusterClient, mockMachineDeploymentCache, mockCAPIClusterCache)

	// Create test Scale object
	scale := createTestScale("test-namespace", "test-md", 3)

	// Set dry run to true
	dryRun := true
	resp, err := validator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
			DryRun:    &dryRun,
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request was denied")
}

func (suite *MachineDeploymentValidatorSuite) TestUpdateOperation() {
	ctrl := gomock.NewController(suite.T())
	defer ctrl.Finish()

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockCAPIClusterCache := fake.NewMockCacheInterface[*capi.Cluster](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)
	mockProvClusterClient := fake.NewMockClientInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Set up expected calls
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{},
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: admission.Ptr(int32(5)),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						capi.ClusterNameLabel:                 "test-cluster",
						"rke.cattle.io/rke-machine-pool-name": "test-machine-pool",
					},
				},
			},
		},
	}, nil)

	mockCAPIClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&capi.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
			OwnerReferences: []v1.OwnerReference{
				{
					APIVersion: "provisioning.cattle.io/v1",
					Kind:       "Cluster",
					Name:       "test-cluster",
				},
			},
		},
		Spec: capi.ClusterSpec{
			InfrastructureRef: &corev1.ObjectReference{
				Name:      "test-cluster",
				Namespace: "test-namespace",
			},
		},
	}, nil)

	// Set up expected call for provisioning cluster cache lookup (called twice: initial + in retry loop)
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
						Quantity: admission.Ptr(int32(2)),
					},
				},
			},
		},
	}, nil)

	// Set up expected call for provisioning cluster client update
	mockProvClusterClient.EXPECT().Update(gomock.Any()).Return(&v2prov.Cluster{}, nil)

	// Create validator with mock clients
	validator := NewValidator(mockProvClusterCache, mockProvClusterClient, mockMachineDeploymentCache, mockCAPIClusterCache)

	// Create test Scale object with 5 replicas (should trigger update)
	scale := createTestScale("test-namespace", "test-md", 5)
	oldScale := createTestScale("test-namespace", "test-md", 2)

	resp, err := validator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Update,
			Object:    runtime.RawExtension{Raw: scale},
			OldObject: runtime.RawExtension{Raw: oldScale},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request was denied")
}
func (suite *MachineDeploymentValidatorSuite) TestCAPIClusterNotFound() {
	ctrl := gomock.NewController(suite.T())
	defer ctrl.Finish()

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockCAPIClusterCache := fake.NewMockCacheInterface[*capi.Cluster](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)
	mockProvClusterClient := fake.NewMockClientInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Set up expected calls
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{},
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: admission.Ptr(int32(3)),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						capi.ClusterNameLabel:                 "test-cluster",
						"rke.cattle.io/rke-machine-pool-name": "test-machine-pool",
					},
				},
			},
		},
	}, nil)

	// CAPI cluster not found - will be called on each retry attempt
	mockCAPIClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(nil, apierrors.NewNotFound(schema.GroupResource{Group: "cluster.x-k8s.io", Resource: "clusters"}, "test-cluster")).AnyTimes()

	// Create validator with mock clients
	validator := NewValidator(mockProvClusterCache, mockProvClusterClient, mockMachineDeploymentCache, mockCAPIClusterCache)

	// Create test Scale object
	scale := createTestScale("test-namespace", "test-md", 3)

	resp, err := validator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	// Should return error when CAPI cluster is not found
	suite.Nil(err)
	suite.True(resp.Allowed, "admission request should be allowed when CAPI cluster not found")
}

func (suite *MachineDeploymentValidatorSuite) TestProvisioningClusterOwnerNotFound() {
	ctrl := gomock.NewController(suite.T())
	defer ctrl.Finish()

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockCAPIClusterCache := fake.NewMockCacheInterface[*capi.Cluster](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)
	mockProvClusterClient := fake.NewMockClientInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Set up expected calls
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{},
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: admission.Ptr(int32(3)),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						capi.ClusterNameLabel:                 "test-cluster",
						"rke.cattle.io/rke-machine-pool-name": "test-machine-pool",
					},
				},
			},
		},
	}, nil)

	// CAPI cluster with no provisioning cluster owner reference
	mockCAPIClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&capi.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
			OwnerReferences: []v1.OwnerReference{
				{
					APIVersion: "infrastructure.cluster.x-k8s.io/v1beta1",
					Kind:       "AWSCluster",
					Name:       "aws-cluster",
				},
			},
		},
		Spec: capi.ClusterSpec{
			InfrastructureRef: &corev1.ObjectReference{
				Name:      "test-cluster",
				Namespace: "test-namespace",
			},
		},
	}, nil)

	// Create validator with mock clients
	validator := NewValidator(mockProvClusterCache, mockProvClusterClient, mockMachineDeploymentCache, mockCAPIClusterCache)

	// Create test Scale object
	scale := createTestScale("test-namespace", "test-md", 3)

	resp, err := validator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	// Should return error when provisioning cluster owner is not found
	suite.Nil(err)
	suite.True(resp.Allowed, "admission request should be allowed when provisioning cluster owner not found")
}

func (suite *MachineDeploymentValidatorSuite) TestProvisioningClusterCacheError() {
	ctrl := gomock.NewController(suite.T())
	defer ctrl.Finish()

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockCAPIClusterCache := fake.NewMockCacheInterface[*capi.Cluster](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)
	mockProvClusterClient := fake.NewMockClientInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Set up expected calls
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{},
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: admission.Ptr(int32(3)),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						capi.ClusterNameLabel:                 "test-cluster",
						"rke.cattle.io/rke-machine-pool-name": "test-machine-pool",
					},
				},
			},
		},
	}, nil)

	mockCAPIClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&capi.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
			OwnerReferences: []v1.OwnerReference{
				{
					APIVersion: "provisioning.cattle.io/v1",
					Kind:       "Cluster",
					Name:       "test-cluster",
				},
			},
		},
		Spec: capi.ClusterSpec{
			InfrastructureRef: &corev1.ObjectReference{
				Name:      "test-cluster",
				Namespace: "test-namespace",
			},
		},
	}, nil)

	// Provisioning cluster cache returns error
	mockProvClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(nil, fmt.Errorf("cache error"))

	// Create validator with mock clients
	validator := NewValidator(mockProvClusterCache, mockProvClusterClient, mockMachineDeploymentCache, mockCAPIClusterCache)

	// Create test Scale object
	scale := createTestScale("test-namespace", "test-md", 3)

	resp, err := validator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	// Should return error when provisioning cluster cache lookup fails
	suite.NotNil(err)
	suite.False(resp.Allowed, "admission request should be denied when provisioning cluster cache lookup fails")
}

func (suite *MachineDeploymentValidatorSuite) TestConflictErrorWithRetry() {
	ctrl := gomock.NewController(suite.T())
	defer ctrl.Finish()

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockCAPIClusterCache := fake.NewMockCacheInterface[*capi.Cluster](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)
	mockProvClusterClient := fake.NewMockClientInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Set up expected calls for MachineDeployment cache lookup
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{},
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: admission.Ptr(int32(3)),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						capi.ClusterNameLabel:                 "test-cluster",
						"rke.cattle.io/rke-machine-pool-name": "test-machine-pool",
					},
				},
			},
		},
	}, nil)

	// Set up expected call for CAPI cluster cache lookup (called once before retry)
	mockCAPIClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&capi.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
			OwnerReferences: []v1.OwnerReference{
				{
					APIVersion: "provisioning.cattle.io/v1",
					Kind:       "Cluster",
					Name:       "test-cluster",
				},
			},
		},
		Spec: capi.ClusterSpec{
			InfrastructureRef: &corev1.ObjectReference{
				Name:      "test-cluster",
				Namespace: "test-namespace",
			},
		},
	}, nil).Times(2)

	// Set up expected call for provisioning cluster cache lookup (called 3 times: initial + first attempt + refetch on conflict)
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
						Quantity: admission.Ptr(int32(2)),
					},
				},
			},
		},
	}, nil).Times(2)

	// First update call returns conflict error, second update call succeeds
	mockProvClusterClient.EXPECT().Update(gomock.Any()).Return(nil, apierrors.NewConflict(schema.GroupResource{Group: "", Resource: "clusters"}, "test-cluster", nil)).Times(1)
	mockProvClusterClient.EXPECT().Update(gomock.Any()).Return(&v2prov.Cluster{}, nil).Times(1)

	// Create validator with mock caches
	validator := NewValidator(mockProvClusterCache, mockProvClusterClient, mockMachineDeploymentCache, mockCAPIClusterCache)

	// Create test Scale object with 3 replicas (should trigger update)
	scale := createTestScale("test-namespace", "test-md", 3)

	resp, err := validator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request was denied")
}

func (suite *MachineDeploymentValidatorSuite) TestProvisioningClusterMissingRKEConfig() {
	ctrl := gomock.NewController(suite.T())
	defer ctrl.Finish()

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockCAPIClusterCache := fake.NewMockCacheInterface[*capi.Cluster](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)
	mockProvClusterClient := fake.NewMockClientInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Set up expected calls for MachineDeployment cache lookup
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{},
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: admission.Ptr(int32(3)),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						capi.ClusterNameLabel:                 "test-cluster",
						"rke.cattle.io/rke-machine-pool-name": "test-machine-pool",
					},
				},
			},
		},
	}, nil)

	// Set up expected call for CAPI cluster cache lookup
	mockCAPIClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&capi.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
			OwnerReferences: []v1.OwnerReference{
				{
					APIVersion: "provisioning.cattle.io/v1",
					Kind:       "Cluster",
					Name:       "test-cluster",
				},
			},
		},
		Spec: capi.ClusterSpec{
			InfrastructureRef: &corev1.ObjectReference{
				Name:      "test-cluster",
				Namespace: "test-namespace",
			},
		},
	}, nil)

	// Set up expected call for provisioning cluster cache lookup - RKEConfig is nil
	mockProvClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&v2prov.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
		},
		Spec: v2prov.ClusterSpec{
			RKEConfig: nil, // RKEConfig is nil
		},
	}, nil)

	// Create validator with mock caches (Update should NOT be called since RKEConfig is nil)
	validator := NewValidator(mockProvClusterCache, mockProvClusterClient, mockMachineDeploymentCache, mockCAPIClusterCache)

	// Create test Scale object
	scale := createTestScale("test-namespace", "test-md", 3)

	resp, err := validator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request should be allowed when RKEConfig is nil")
}

func (suite *MachineDeploymentValidatorSuite) TestProvisioningClusterEmptyMachinePools() {
	ctrl := gomock.NewController(suite.T())
	defer ctrl.Finish()

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockCAPIClusterCache := fake.NewMockCacheInterface[*capi.Cluster](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)
	mockProvClusterClient := fake.NewMockClientInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Set up expected calls for MachineDeployment cache lookup
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{},
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: admission.Ptr(int32(3)),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						capi.ClusterNameLabel:                 "test-cluster",
						"rke.cattle.io/rke-machine-pool-name": "test-machine-pool",
					},
				},
			},
		},
	}, nil)

	// Set up expected call for CAPI cluster cache lookup
	mockCAPIClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&capi.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
			OwnerReferences: []v1.OwnerReference{
				{
					APIVersion: "provisioning.cattle.io/v1",
					Kind:       "Cluster",
					Name:       "test-cluster",
				},
			},
		},
		Spec: capi.ClusterSpec{
			InfrastructureRef: &corev1.ObjectReference{
				Name:      "test-cluster",
				Namespace: "test-namespace",
			},
		},
	}, nil)

	// Set up expected call for provisioning cluster cache lookup - MachinePools is empty
	mockProvClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&v2prov.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
		},
		Spec: v2prov.ClusterSpec{
			RKEConfig: &v2prov.RKEConfig{
				MachinePools: []v2prov.RKEMachinePool{}, // Empty MachinePools
			},
		},
	}, nil)

	// Create validator with mock caches (Update should NOT be called since MachinePools is empty)
	validator := NewValidator(mockProvClusterCache, mockProvClusterClient, mockMachineDeploymentCache, mockCAPIClusterCache)

	// Create test Scale object
	scale := createTestScale("test-namespace", "test-md", 3)

	resp, err := validator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request should be allowed when MachinePools is empty")
}

func (suite *MachineDeploymentValidatorSuite) TestInvalidScaleObject() {
	ctrl := gomock.NewController(suite.T())
	defer ctrl.Finish()

	// Create mock caches (should not be called since scale parsing will fail)
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockCAPIClusterCache := fake.NewMockCacheInterface[*capi.Cluster](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)
	mockProvClusterClient := fake.NewMockClientInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Create validator with mock clients
	validator := NewValidator(mockProvClusterCache, mockProvClusterClient, mockMachineDeploymentCache, mockCAPIClusterCache)

	// Create admission request with invalid JSON that will fail unmarshaling
	invalidJSON := []byte(`{"spec": {invalid}}`)
	resp, err := validator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: invalidJSON},
		}})

	suite.Nil(err)
	suite.False(resp.Allowed, "admission request should be denied when scale object is invalid")
	suite.Equal(resp.Result.Code, int32(400), "the request should be a 400 bad request")
}

func (suite *MachineDeploymentValidatorSuite) TestMissingMachinePoolLabel() {
	ctrl := gomock.NewController(suite.T())
	defer ctrl.Finish()

	// Create mock caches
	mockMachineDeploymentCache := fake.NewMockCacheInterface[*capi.MachineDeployment](ctrl)
	mockCAPIClusterCache := fake.NewMockCacheInterface[*capi.Cluster](ctrl)
	mockProvClusterCache := fake.NewMockCacheInterface[*v2prov.Cluster](ctrl)
	mockProvClusterClient := fake.NewMockClientInterface[*v2prov.Cluster, *v2prov.ClusterList](ctrl)

	// Set up expected call for MachineDeployment cache lookup - has cluster name label but missing machine pool label
	mockMachineDeploymentCache.EXPECT().Get("test-namespace", "test-md").Return(&capi.MachineDeployment{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-md",
			Namespace: "test-namespace",
			Labels:    map[string]string{},
		},
		Spec: capi.MachineDeploymentSpec{
			Replicas: admission.Ptr(int32(3)),
			Template: capi.MachineTemplateSpec{
				ObjectMeta: capi.ObjectMeta{
					Labels: map[string]string{
						capi.ClusterNameLabel: "test-cluster", // Has cluster name label
						// Missing rke.cattle.io/rke-machine-pool-name label
					},
				},
			},
		},
	}, nil)

	// Set up expected call for CAPI cluster cache lookup
	mockCAPIClusterCache.EXPECT().Get("test-namespace", "test-cluster").Return(&capi.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: "test-namespace",
			OwnerReferences: []v1.OwnerReference{
				{
					APIVersion: "provisioning.cattle.io/v1",
					Kind:       "Cluster",
					Name:       "test-cluster",
				},
			},
		},
		Spec: capi.ClusterSpec{
			InfrastructureRef: &corev1.ObjectReference{
				Name:      "test-cluster",
				Namespace: "test-namespace",
			},
		},
	}, nil)

	// Set up expected call for provisioning cluster cache lookup (will be called but Update won't since machine pool name is empty)
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
						Quantity: admission.Ptr(int32(2)),
					},
				},
			},
		},
	}, nil)

	// Create validator with mock clients
	validator := NewValidator(mockProvClusterCache, mockProvClusterClient, mockMachineDeploymentCache, mockCAPIClusterCache)

	// Create test Scale object
	scale := createTestScale("test-namespace", "test-md", 3)

	resp, err := validator.Admit(&admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object:    runtime.RawExtension{Raw: scale},
		}})

	suite.Nil(err)
	suite.True(resp.Allowed, "admission request should be allowed when machine pool label is missing")
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
