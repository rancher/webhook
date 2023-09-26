package project

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/wrangler/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestProjectValidation(t *testing.T) {
	t.Parallel()
	type testState struct {
		clusterCache *fake.MockNonNamespacedCacheInterface[*v3.Cluster]
	}
	tests := []struct {
		name        string
		operation   v1.Operation
		stateSetup  func(state *testState)
		newProject  *v3.Project
		oldProject  *v3.Project
		wantAllowed bool
		wantErr     bool
	}{
		{
			name:        "failure to decode project returns error",
			newProject:  nil,
			oldProject:  nil,
			wantAllowed: false,
			wantErr:     true,
		},
		{
			name:      "no clusterName",
			operation: v1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "c-123xyz",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test1",
				},
			},
			oldProject:  nil,
			wantAllowed: false,
		},
		{
			name:      "clusterName doesn't match namespace",
			operation: v1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "c-123xyz",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test1",
					ClusterName: "some other cluster",
				},
			},
			oldProject:  nil,
			wantAllowed: false,
		},
		{
			name:      "clusterName not found",
			operation: v1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test1",
					ClusterName: "default",
				},
			},
			stateSetup: func(state *testState) {
				clusterGR := schema.GroupResource{
					Group:    "management.cattle.io",
					Resource: "clusters",
				}
				state.clusterCache.EXPECT().Get("default").Return(nil, apierrors.NewNotFound(clusterGR, "default"))
			},
			oldProject:  nil,
			wantAllowed: false,
		},
		{
			name:      "error when validating if the cluster exists",
			operation: v1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test1",
					ClusterName: "default",
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("default").Return(nil, fmt.Errorf("server not available"))
			},
			oldProject:  nil,
			wantAllowed: false,
			wantErr:     true,
		},
		{
			name:      "nil return from the cluster cache",
			operation: v1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "default",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test1",
					ClusterName: "default",
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("default").Return(nil, nil)
			},
			oldProject:  nil,
			wantAllowed: false,
			wantErr:     false,
		},

		{
			name:      "create new with no quotas",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test1",
					ClusterName: "testcluster",
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: true,
		},
		{
			name:      "create new with valid quotas",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test",
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: true,
		},
		{
			name:      "create new with project quota present but namespace quota missing",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test",
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: false,
		},
		{
			name:      "create new with namespace quota present but project quota missing",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test",
					ClusterName: "testcluster",
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: false,
		},
		{
			name:      "create new with namespace quota having unexpected resource fields",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test",
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
							LimitsCPU:  "10m",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: false,
		},
		{
			name:      "create new with project quota having unexpected resource fields",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test",
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
							LimitsCPU:  "10m",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: false,
		},
		{
			name:      "create new with project quota and namespace quota having mismatched resource fields",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					DisplayName: "test",
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
							LimitsCPU:  "10m",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps:   "10",
							LimitsMemory: "2048Mi",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: false,
		},
		{
			name:      "create new with namespace quota greater than project quota",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: false,
		},
		{
			name:      "create new with negative namespace quota",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "-100",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: false,
		},
		{
			name:      "update with no quotas (noop)",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: true,
		},
		{
			name:      "update to reset quotas",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName:                   "testcluster",
					ResourceQuota:                 nil,
					NamespaceDefaultResourceQuota: nil,
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: true,
		},
		{
			name:      "update with new valid quotas",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: true,
		},
		{
			name:      "update with project quota present but namespace quota missing",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: false,
		},
		{
			name:      "update with namespace quota present but project quota missing",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: false,
		},
		{
			name:      "update with namespace quota having unexpected resource fields",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
							LimitsCPU:  "10m",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: false,
		},
		{
			name:      "update with project quota having unexpected resource fields",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
							LimitsCPU:  "10m",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: false,
		},
		{
			name:      "update with project quota and namespace quota having mismatched resource fields",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
							LimitsCPU:  "10m",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps:   "10",
							LimitsMemory: "2048Mi",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: false,
		},
		{
			name:      "update with namespace quota greater than project quota",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: false,
		},
		{
			name:      "update with project quota less than used quota",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
						UsedLimit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "50",
						},
					},
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "60",
						},
						UsedLimit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "50",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: false,
		},
		{
			name:      "update with fields changed in project quota less than used quota",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							LimitsCPU: "100m",
						},
						UsedLimit: v3.ResourceQuotaLimit{
							LimitsCPU: "100m",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							LimitsCPU: "50m",
						},
					},
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
						UsedLimit: v3.ResourceQuotaLimit{
							LimitsCPU: "100m",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "50",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: true,
		},
		{
			name:      "delete regular project",
			operation: admissionv1.Delete,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
			},
			wantAllowed: true,
		},
		{
			name:      "delete system project",
			operation: admissionv1.Delete,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Labels: map[string]string{
						"authz.management.cattle.io/system-project": "true",
					},
				},
			},
			wantAllowed: false,
		},
		{
			name:      "update with negative namespace quota",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "10",
						},
					},
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
					ResourceQuota: &v3.ProjectResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "100",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "-200",
						},
					},
				},
			},
			stateSetup: func(state *testState) {
				state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
					ObjectMeta: metav1.ObjectMeta{
						Name: "testcluster",
					},
				}, nil)
			},
			wantAllowed: false,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			state := testState{
				clusterCache: fake.NewMockNonNamespacedCacheInterface[*v3.Cluster](ctrl),
			}
			if test.stateSetup != nil {
				test.stateSetup(&state)
			}
			req, err := createProjectRequest(test.oldProject, test.newProject, test.operation, false)
			assert.NoError(t, err)
			validator := NewValidator(state.clusterCache)
			admitters := validator.Admitters()
			assert.Len(t, admitters, 1)
			response, err := admitters[0].Admit(req)
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, test.wantAllowed, response.Allowed)
		})
	}
}

func createProjectRequest(oldProject, newProject *v3.Project, operation v1.Operation, dryRun bool) (*admission.Request, error) {
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "Project"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "projects"}
	req := &admission.Request{
		Context: context.Background(),
	}
	if oldProject == nil && newProject == nil {
		return req, nil
	}
	req.AdmissionRequest = v1.AdmissionRequest{
		Kind:            gvk,
		Resource:        gvr,
		RequestKind:     &gvk,
		RequestResource: &gvr,
		Operation:       operation,
		Object:          runtime.RawExtension{},
		OldObject:       runtime.RawExtension{},
		DryRun:          &dryRun,
	}
	if newProject != nil {
		var err error
		req.Object.Raw, err = json.Marshal(newProject)
		if err != nil {
			return nil, err
		}
	}
	if oldProject != nil {
		obj, err := json.Marshal(oldProject)
		if err != nil {
			return nil, err
		}
		req.OldObject = runtime.RawExtension{
			Raw: obj,
		}
	}
	return req, nil
}
