package project

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/common"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestConvertLimitToResourceList(t *testing.T) {
	t.Run("ConvertLimitToResourceList", func(t *testing.T) {
		out, err := convertLimitToResourceList(&v3.ResourceQuotaLimit{
			ConfigMaps:             "1",
			LimitsCPU:              "2",
			LimitsMemory:           "3",
			PersistentVolumeClaims: "4",
			Pods:                   "5",
			ReplicationControllers: "6",
			RequestsCPU:            "7",
			RequestsMemory:         "8",
			RequestsStorage:        "9",
			Secrets:                "10",
			Services:               "11",
			ServicesLoadBalancers:  "12",
			ServicesNodePorts:      "13",
			Extended: map[string]string{
				"ephemeral-storage": "14",
			},
		})
		assert.NoError(t, err)
		assert.Equal(t, corev1.ResourceList{
			"configmaps":             resource.MustParse("1"),
			"ephemeral-storage":      resource.MustParse("14"),
			"limits.cpu":             resource.MustParse("2"),
			"limits.memory":          resource.MustParse("3"),
			"persistentvolumeclaims": resource.MustParse("4"),
			"pods":                   resource.MustParse("5"),
			"replicationcontrollers": resource.MustParse("6"),
			"requests.cpu":           resource.MustParse("7"),
			"requests.memory":        resource.MustParse("8"),
			"requests.storage":       resource.MustParse("9"),
			"secrets":                resource.MustParse("10"),
			"services":               resource.MustParse("11"),
			"services.loadbalancers": resource.MustParse("12"),
			"services.nodeports":     resource.MustParse("13"),
		}, out)
	})
}

func TestProjectValidation(t *testing.T) {
	t.Parallel()
	type testState struct {
		clusterCache *fake.MockNonNamespacedCacheInterface[*v3.Cluster]
		userCache    *fake.MockNonNamespacedCacheInterface[*v3.User]
	}
	tests := []struct {
		name        string
		operation   admissionv1.Operation
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
			operation: admissionv1.Create,
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
			operation: admissionv1.Create,
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
			operation: admissionv1.Create,
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
			operation: admissionv1.Create,
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
			operation: admissionv1.Create,
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
			name:      "create with no-creator-rbac annotation",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.NoCreatorRBACAnn: "true",
					},
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
			name:      "create with no-creator-rbac and creatorID annotation",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.NoCreatorRBACAnn: "true",
						common.CreatorIDAnn:     "u-12345",
					},
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
			wantAllowed: false,
		},
		{
			name:      "update with no-creator-rbac annotation",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.NoCreatorRBACAnn: "true",
					},
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.NoCreatorRBACAnn: "true",
					},
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			wantAllowed: true,
		},
		{
			name:      "update adding no-creator-rbac",
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
					Annotations: map[string]string{
						common.NoCreatorRBACAnn: "true",
					},
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			wantAllowed: false,
		},
		{
			name:      "update modifying no-creator-rbac",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.NoCreatorRBACAnn: "true",
					},
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.NoCreatorRBACAnn: "false",
					},
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			wantAllowed: false,
		},
		{
			name:      "update removing no-creator-rbac",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.NoCreatorRBACAnn: "true",
					},
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
			name:      "create with principal name annotation",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.CreatorPrincipalNameAnn: "keycloak_user://12345",
						common.CreatorIDAnn:            "u-12345",
					},
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
				state.userCache.EXPECT().Get("u-12345").Return(&v3.User{
					ObjectMeta: metav1.ObjectMeta{
						Name: "u-12345",
					},
					PrincipalIDs: []string{"local://u-12345", "keycloak_user://12345"},
				}, nil)
			},
			wantAllowed: true,
		},
		{
			name:      "create with principal name annotation but no creator id",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
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
				state.userCache.EXPECT().Get("u-12345").Times(0)
			},
			wantAllowed: false,
		},
		{
			name:      "create with principal name annotation that doesn't belong to creator id",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.CreatorPrincipalNameAnn: "keycloak_user://12346",
						common.CreatorIDAnn:            "u-12345",
					},
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
				state.userCache.EXPECT().Get("u-12345").Return(&v3.User{
					ObjectMeta: metav1.ObjectMeta{
						Name: "u-12345",
					},
					PrincipalIDs: []string{"local://u-12345", "keycloak_user://12345"},
				}, nil)
			},
			wantAllowed: false,
		},
		{
			name:      "create with principal name annotation but creator doesn't exist",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.CreatorPrincipalNameAnn: "keycloak_user://12346",
						common.CreatorIDAnn:            "u-12345",
					},
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
				state.userCache.EXPECT().Get("u-12345").Return(nil, apierrors.NewNotFound(schema.GroupResource{}, "u-12345"))
			},
			wantAllowed: false,
		},
		{
			name:      "create with principal name annotation but error getting creator id",
			operation: admissionv1.Create,
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.CreatorPrincipalNameAnn: "keycloak_user://12346",
						common.CreatorIDAnn:            "u-12345",
					},
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
				state.userCache.EXPECT().Get("u-12345").Return(nil, fmt.Errorf("some error"))
			},
			wantAllowed: false,
			wantErr:     true,
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
			name:      "update with project quota less than used quota, quota changed",
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
			name:      "update with project quota less than used quota, used quota changed",
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
							ConfigMaps: "100",
						},
						UsedLimit: v3.ResourceQuotaLimit{
							ConfigMaps: "1000",
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
			name:      "update project with bogus used quota, to good used quota",
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
							ConfigMaps: "xxxxxxxxxx",
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
			wantAllowed: true,
		},
		{
			name:      "update project with good used quota, to bogus used quota",
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
							ConfigMaps: "100",
						},
						UsedLimit: v3.ResourceQuotaLimit{
							ConfigMaps: "xxxxxxxxxx",
						},
					},
					NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
						Limit: v3.ResourceQuotaLimit{
							ConfigMaps: "50",
						},
					},
				},
			},
			wantErr:     true,
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
			name:      "update changing creator id annotation",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.CreatorIDAnn: "u-12345",
					},
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "tescluster",
					Annotations: map[string]string{
						common.CreatorIDAnn: "u-12346",
					},
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			wantAllowed: false,
		},
		{
			name:      "update changing principle name annotation",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "tescluster",
					Annotations: map[string]string{
						common.CreatorPrincipalNameAnn: "keycloak_user://12346",
					},
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			wantAllowed: false,
		},
		{
			name:      "update removing creator annotations",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.CreatorIDAnn:            "u-12345",
						common.CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "tescluster",
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			wantAllowed: true,
		},
		{
			name:      "update without changing creator annotations",
			operation: admissionv1.Update,
			oldProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "testcluster",
					Annotations: map[string]string{
						common.CreatorIDAnn:            "u-12345",
						common.CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			newProject: &v3.Project{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test",
					Namespace: "tescluster",
					Annotations: map[string]string{
						common.CreatorIDAnn:            "u-12345",
						common.CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
				},
				Spec: v3.ProjectSpec{
					ClusterName: "testcluster",
				},
			},
			wantAllowed: true,
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
				userCache:    fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl),
			}
			if test.stateSetup != nil {
				test.stateSetup(&state)
			}
			req, err := createProjectRequest(test.oldProject, test.newProject, test.operation, false)
			assert.NoError(t, err)
			validator := NewValidator(state.clusterCache, state.userCache)
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
		operation   admissionv1.Operation
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
				validator := NewValidator(state.clusterCache, nil)
				admitters := validator.Admitters()
				assert.Len(t, admitters, 1)
				response, err := admitters[0].Admit(req)
				assert.NoError(t, err)
				assert.Equal(t, test.wantAllowed, response.Allowed)
			})
		}
	}
}

func createProjectRequest(oldProject, newProject *v3.Project, operation admissionv1.Operation, dryRun bool) (*admission.Request, error) {
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "Project"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "projects"}
	req := &admission.Request{
		Context: context.Background(),
	}
	if oldProject == nil && newProject == nil {
		return req, nil
	}
	req.AdmissionRequest = admissionv1.AdmissionRequest{
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
