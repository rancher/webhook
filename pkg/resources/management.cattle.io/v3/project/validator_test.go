package project

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
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
			wantAllowed: false,
		},
		{
			name:      "update changing clusterName",
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
					Namespace: "testothercluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testothercluster",
				},
			},
			wantAllowed: false,
		},
		{
			name:      "invalid operation",
			operation: admissionv1.Connect,
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
			wantAllowed: false,
			wantErr:     true,
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

func TestProjectContainerDefaultLimitsValidation(t *testing.T) {
	t.Parallel()
	type testState struct {
		clusterCache *fake.MockNonNamespacedCacheInterface[*v3.Cluster]
	}
	tests := []struct {
		name        string
		operation   v1.Operation
		limit       *v3.ContainerResourceLimit
		wantAllowed bool
	}{
		{
			name:        "nil requests and limits",
			wantAllowed: true,
		},
		{
			name:        "empty requests and limits",
			limit:       &v3.ContainerResourceLimit{},
			wantAllowed: true,
		},
		{
			name: "cpu and memory request and limits",
			limit: &v3.ContainerResourceLimit{
				RequestsCPU:    "1m",
				LimitsCPU:      "20m",
				RequestsMemory: "1Mi",
				LimitsMemory:   "20Mi",
			},
			wantAllowed: true,
		},
		{
			name: "only cpu request and limit",
			limit: &v3.ContainerResourceLimit{
				RequestsCPU: "1m",
				LimitsCPU:   "20m",
			},
			wantAllowed: true,
		},
		{
			name: "only memory request and limit",
			limit: &v3.ContainerResourceLimit{
				RequestsMemory: "1Mi",
				LimitsMemory:   "20Mi",
			},
			wantAllowed: true,
		},
		{
			name: "only cpu request",
			limit: &v3.ContainerResourceLimit{
				RequestsCPU: "1m",
			},
			wantAllowed: true,
		},
		{
			name: "only cpu limit",
			limit: &v3.ContainerResourceLimit{
				LimitsCPU: "20m",
			},
			wantAllowed: true,
		},
		{
			name: "only memory request",
			limit: &v3.ContainerResourceLimit{
				RequestsMemory: "1Mi",
			},
			wantAllowed: true,
		},
		{
			name: "only memory limit",
			limit: &v3.ContainerResourceLimit{
				LimitsMemory: "20Mi",
			},
			wantAllowed: true,
		},
		{
			name: "cpu and memory requests equal to limits",
			limit: &v3.ContainerResourceLimit{
				RequestsCPU:    "20m",
				LimitsCPU:      "20m",
				RequestsMemory: "30Mi",
				LimitsMemory:   "30Mi",
			},
			wantAllowed: true,
		},
		{
			name: "cpu request over limit",
			limit: &v3.ContainerResourceLimit{
				RequestsCPU: "30m",
				LimitsCPU:   "20m",
			},
		},
		{
			name: "positive memory request over negative limit",
			limit: &v3.ContainerResourceLimit{
				RequestsMemory: "500Mi",
				LimitsMemory:   "-20Mi",
			},
		},
		{
			name: "cpu and memory requests both over limits",
			limit: &v3.ContainerResourceLimit{
				RequestsCPU:    "30m",
				LimitsCPU:      "20m",
				RequestsMemory: "30Mi",
				LimitsMemory:   "20Mi",
			},
		},
		{
			name: "cpu limit is zero while request is positive",
			limit: &v3.ContainerResourceLimit{
				RequestsCPU: "20m",
				LimitsCPU:   "0m",
			},
		},
		{
			name: "memory limit is zero while request is positive",
			limit: &v3.ContainerResourceLimit{
				RequestsMemory: "20Mi",
				LimitsMemory:   "0Mi",
			},
		},
		{
			name: "invalid value on cpu request causes an error",
			limit: &v3.ContainerResourceLimit{
				RequestsCPU:    "apple",
				LimitsCPU:      "20m",
				RequestsMemory: "1Mi",
				LimitsMemory:   "20Mi",
			},
		},
		{
			name: "invalid value on cpu limit causes an error",
			limit: &v3.ContainerResourceLimit{
				RequestsCPU:    "1m",
				LimitsCPU:      "apple",
				RequestsMemory: "1Mi",
				LimitsMemory:   "20Mi",
			},
		},
		{
			name: "invalid value on memory request causes an error",
			limit: &v3.ContainerResourceLimit{
				RequestsCPU:    "1m",
				LimitsCPU:      "20m",
				RequestsMemory: "apple",
				LimitsMemory:   "20Mi",
			},
		},
		{
			name: "invalid value on memory limit causes an error",
			limit: &v3.ContainerResourceLimit{
				RequestsCPU:    "1m",
				LimitsCPU:      "20m",
				RequestsMemory: "1Mi",
				LimitsMemory:   "apple",
			},
		},
	}

	for _, test := range tests {
		for _, operation := range []admissionv1.Operation{admissionv1.Create, admissionv1.Update} {
			test.operation = operation
			name := fmt.Sprintf("%s on %s", test.name, strings.ToLower(string(test.operation)))
			t.Run(name, func(t *testing.T) {
				oldProject := &v3.Project{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "test",
						Namespace: "testcluster",
					},
					Spec: v3.ProjectSpec{
						ClusterName:                   "testcluster",
						ContainerDefaultResourceLimit: test.limit,
					},
				}
				newProject := oldProject
				ctrl := gomock.NewController(t)
				state := testState{
					clusterCache: fake.NewMockNonNamespacedCacheInterface[*v3.Cluster](ctrl),
				}
				if test.operation == admissionv1.Create {
					oldProject = nil
					state.clusterCache.EXPECT().Get("testcluster").Return(&v3.Cluster{
						ObjectMeta: metav1.ObjectMeta{
							Name: "testcluster",
						},
					}, nil)
				}
				req, err := createProjectRequest(oldProject, newProject, test.operation, false)
				assert.NoError(t, err)
				validator := NewValidator(state.clusterCache)
				admitters := validator.Admitters()
				assert.Len(t, admitters, 1)
				response, err := admitters[0].Admit(req)
				assert.NoError(t, err)
				assert.Equal(t, test.wantAllowed, response.Allowed)
			})
		}
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
