package cluster

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/common"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	k8sv1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	v1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

type mockReviewer struct {
	v1.SubjectAccessReviewExpansion
}

func (m *mockReviewer) Create(
	_ context.Context,
	_ *authorizationv1.SubjectAccessReview,
	_ metav1.CreateOptions,
) (*authorizationv1.SubjectAccessReview, error) {
	return &authorizationv1.SubjectAccessReview{
		Status: authorizationv1.SubjectAccessReviewStatus{
			Allowed: true,
		},
	}, nil
}

func TestAdmit(t *testing.T) {
	ctrl := gomock.NewController(t)
	userCache := fake.NewMockNonNamespacedCacheInterface[*v3.User](ctrl)
	userCache.EXPECT().Get(gomock.Any()).DoAndReturn(func(name string) (*v3.User, error) {
		if name == "u-12345" {
			return &v3.User{
				ObjectMeta: metav1.ObjectMeta{
					Name: "u-12345",
				},
				PrincipalIDs: []string{"keycloak_user://12345"},
			}, nil
		}

		return nil, apierrors.NewNotFound(schema.GroupResource{}, name)
	}).AnyTimes()

	settingCache := fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)
	settingCache.EXPECT().Get(gomock.Any()).DoAndReturn(func(name string) (*v3.Setting, error) {
		if name == VersionManagementSetting {
			return &v3.Setting{
				Value: "true",
			}, nil
		}
		return nil, apierrors.NewNotFound(schema.GroupResource{}, name)
	}).AnyTimes()

	tests := []struct {
		name           string
		oldCluster     v3.Cluster
		newCluster     v3.Cluster
		operation      admissionv1.Operation
		expectAllowed  bool
		expectedReason metav1.StatusReason
	}{
		{
			name:          "Create",
			operation:     admissionv1.Create,
			expectAllowed: true,
		},
		{
			name: "Create with creator principal",
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.CreatorIDAnn:            "u-12345",
						common.CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
				},
			},
			operation:     admissionv1.Create,
			expectAllowed: true,
		},
		{
			name: "Create with creator principal but no creator id",
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
				},
			},
			operation:      admissionv1.Create,
			expectAllowed:  false,
			expectedReason: metav1.StatusReasonBadRequest,
		},
		{
			name: "Create with creator principal and non-existent creator id",
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.CreatorIDAnn:            "u-12346",
						common.CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
				},
			},
			operation:      admissionv1.Create,
			expectAllowed:  false,
			expectedReason: metav1.StatusReasonBadRequest,
		},
		{
			name:           "UpdateWithUnsetFleetWorkspaceName",
			oldCluster:     v3.Cluster{Spec: v3.ClusterSpec{FleetWorkspaceName: "fleet-default"}},
			operation:      admissionv1.Update,
			expectAllowed:  false,
			expectedReason: metav1.StatusReasonInvalid,
		},
		{
			name:          "UpdateWithNewFleetWorkspaceName",
			oldCluster:    v3.Cluster{Spec: v3.ClusterSpec{FleetWorkspaceName: "fleet-default"}},
			newCluster:    v3.Cluster{Spec: v3.ClusterSpec{FleetWorkspaceName: "new"}},
			operation:     admissionv1.Update,
			expectAllowed: true,
		},
		{
			name:          "UpdateWithUnchangedFleetWorkspaceName",
			oldCluster:    v3.Cluster{Spec: v3.ClusterSpec{FleetWorkspaceName: "fleet-default"}},
			newCluster:    v3.Cluster{Spec: v3.ClusterSpec{FleetWorkspaceName: "fleet-default"}},
			operation:     admissionv1.Update,
			expectAllowed: true,
		},
		{
			name: "Update changing creator id annotation",
			oldCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.CreatorIDAnn: "u-12345",
					},
				},
			},
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.CreatorIDAnn: "u-12346",
					},
				},
			},
			operation:      admissionv1.Update,
			expectAllowed:  false,
			expectedReason: metav1.StatusReasonBadRequest,
		},
		{
			name: "Update changing principle name annotation",
			oldCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
				},
			},
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.CreatorPrincipalNameAnn: "keycloak_user://12346",
					},
				},
			},
			operation:      admissionv1.Update,
			expectAllowed:  false,
			expectedReason: metav1.StatusReasonBadRequest,
		},
		{
			name: "Update removing creator annotations",
			oldCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.CreatorIDAnn:            "u-12345",
						common.CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
				},
			},
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
				},
			},
			operation:      admissionv1.Update,
			expectAllowed:  true,
			expectedReason: metav1.StatusReasonBadRequest,
		},
		{
			name: "Update without changing creator annotations",
			oldCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.CreatorIDAnn:            "u-12345",
						common.CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
				},
			},
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.CreatorIDAnn:            "u-12345",
						common.CreatorPrincipalNameAnn: "keycloak_user://12345",
					},
				},
			},
			operation:      admissionv1.Update,
			expectAllowed:  true,
			expectedReason: metav1.StatusReasonBadRequest,
		},
		{
			name:          "Delete",
			oldCluster:    v3.Cluster{Spec: v3.ClusterSpec{FleetWorkspaceName: "fleet-default"}},
			operation:     admissionv1.Delete,
			expectAllowed: true,
		},
		{
			name:      "Create with no-creator-rbac annotation",
			operation: admissionv1.Create,
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.NoCreatorRBACAnn: "true",
					},
				},
			},
			expectAllowed: true,
		},
		{
			name:      "Create with no-creator-rbac and creatorID annotation",
			operation: admissionv1.Create,
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.NoCreatorRBACAnn: "true",
						common.CreatorIDAnn:     "u-12345",
					},
				},
			},
			expectAllowed:  false,
			expectedReason: metav1.StatusReasonBadRequest,
		},
		{
			name:      "Update with no-creator-rbac annotation",
			operation: admissionv1.Update,
			oldCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.NoCreatorRBACAnn: "true",
					},
				},
			},
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.NoCreatorRBACAnn: "true",
					},
				},
			},
			expectAllowed: true,
		},
		{
			name:      "Update modifying no-creator-rbac annotation",
			operation: admissionv1.Update,
			oldCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
				},
			},
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.NoCreatorRBACAnn: "true",
					},
				},
			},
			expectAllowed: false,
		},
		{
			name:      "Update removing no-creator-rbac",
			operation: admissionv1.Create,
			oldCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
					Annotations: map[string]string{
						common.NoCreatorRBACAnn: "true",
					},
				},
			},
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "c-2bmj5",
				},
			},
			expectAllowed:  true,
			expectedReason: metav1.StatusReasonBadRequest,
		},
		// Test cases for the version management feature
		{
			name:      "cluster version management - imported RKE2 cluster,valid annotation, create",
			operation: admissionv1.Create,
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						VersionManagementAnno: "false",
					},
				},
				Status: v3.ClusterStatus{
					Driver: v3.ClusterDriverRke2,
				},
			},
			expectAllowed: true,
		},

		{
			name:      "cluster version management - imported RKE2 cluster,no annotation, create",
			operation: admissionv1.Create,
			newCluster: v3.Cluster{
				Status: v3.ClusterStatus{
					Driver: v3.ClusterDriverRke2,
				},
			},
			expectAllowed:  false,
			expectedReason: metav1.StatusReasonBadRequest,
		},
		{
			name:      "cluster version management - imported K3s cluster,valid annotation, create",
			operation: admissionv1.Create,
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						VersionManagementAnno: "true",
					},
				},
				Status: v3.ClusterStatus{
					Driver: v3.ClusterDriverK3s,
				},
			},
			expectAllowed: true,
		},
		{
			name:      "cluster version management - imported K3s cluster,valid annotation, update",
			operation: admissionv1.Update,
			oldCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						VersionManagementAnno: "false",
					},
				},
				Status: v3.ClusterStatus{
					Driver: v3.ClusterDriverK3s,
				},
			},
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						VersionManagementAnno: "system-default",
					},
				},
				Status: v3.ClusterStatus{
					Driver: v3.ClusterDriverK3s,
				},
			},
			expectAllowed: true,
		},
		{
			name:      "cluster version management - imported K3s cluster,drop annotation, update",
			operation: admissionv1.Update,
			oldCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						VersionManagementAnno: "system-default",
					},
				},
				Status: v3.ClusterStatus{
					Driver: v3.ClusterDriverK3s,
				},
			},
			newCluster: v3.Cluster{
				Status: v3.ClusterStatus{
					Driver: v3.ClusterDriverK3s,
				},
			},
			expectAllowed:  false,
			expectedReason: metav1.StatusReasonBadRequest,
		},
		{
			name:      "cluster version management - imported RKE2 cluster,invalid annotation, update",
			operation: admissionv1.Update,
			oldCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						VersionManagementAnno: "false",
					},
				},
				Status: v3.ClusterStatus{
					Driver: v3.ClusterDriverK3s,
				},
			},
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						VersionManagementAnno: "INVALID",
					},
				},
				Status: v3.ClusterStatus{
					Driver: v3.ClusterDriverRke2,
				},
			},
			expectAllowed:  false,
			expectedReason: metav1.StatusReasonBadRequest,
		},
		{
			name:      "cluster version management - invalid cluster type, valid annotation, create",
			operation: admissionv1.Create,
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						VersionManagementAnno: "false",
					},
				},
				Status: v3.ClusterStatus{
					Driver: v3.ClusterDriverAKS,
				},
			},
			expectAllowed: true,
		},
		{
			name:      "cluster version management - invalid cluster type, invalid annotation, update",
			operation: admissionv1.Create,
			oldCluster: v3.Cluster{
				Status: v3.ClusterStatus{
					Driver: v3.ClusterDriverAKS,
				},
			},
			newCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						VersionManagementAnno: "INVALID",
					},
				},
				Status: v3.ClusterStatus{
					Driver: v3.ClusterDriverAKS,
				},
			},
			expectAllowed: true,
		},
		{
			name:      "Delete local cluster where Rancher is deployed",
			operation: admissionv1.Delete,
			oldCluster: v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "local",
				},
			},
			expectAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{
				admitter: admitter{
					sar:          &mockReviewer{},
					userCache:    userCache,
					settingCache: settingCache,
				},
			}

			oldClusterBytes, err := json.Marshal(tt.oldCluster)
			assert.NoError(t, err)
			newClusterBytes, err := json.Marshal(tt.newCluster)
			assert.NoError(t, err)

			admitters := v.Admitters()
			assert.Len(t, admitters, 1)

			res, err := admitters[0].Admit(&admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Object: runtime.RawExtension{
						Raw: newClusterBytes,
					},
					OldObject: runtime.RawExtension{
						Raw: oldClusterBytes,
					},
					Operation: tt.operation,
				},
			})
			assert.NoError(t, err)
			assert.Equal(t, tt.expectAllowed, res.Allowed)

			if !tt.expectAllowed {
				if tt.expectedReason != "" {
					assert.Equal(t, tt.expectedReason, res.Result.Reason)
				}
			}
		})
	}
}

func Test_versionManagementEnabled(t *testing.T) {
	ctrl := gomock.NewController(t)
	settingCache := fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)
	settingCache.EXPECT().Get(gomock.Any()).DoAndReturn(func(name string) (*v3.Setting, error) {
		if name == VersionManagementSetting {
			return &v3.Setting{
				Value: "true",
			}, nil
		}
		return nil, apierrors.NewNotFound(schema.GroupResource{}, name)
	}).AnyTimes()

	tests := []struct {
		name         string
		cluster      *v3.Cluster
		expectError  bool
		expectResult bool
	}{
		{
			name:         "nil cluster",
			cluster:      nil,
			expectError:  true,
			expectResult: false,
		},
		{
			name: "no annotation",
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "cluster",
				},
			},
			expectError:  true,
			expectResult: false,
		},
		{
			name: "annotation value false",
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						VersionManagementAnno: "false",
					},
				},
			},
			expectError:  false,
			expectResult: false,
		},
		{
			name: "annotation value true",
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						VersionManagementAnno: "true",
					},
				},
			},
			expectError:  false,
			expectResult: true,
		}, {
			name: "annotation value system-default",
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						VersionManagementAnno: "system-default",
					},
				},
			},
			expectError:  false,
			expectResult: true,
		}, {
			name: "annotation value invalid",
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						VersionManagementAnno: "INVALID",
					},
				},
			},
			expectError:  true,
			expectResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &admitter{
				settingCache: settingCache,
			}
			got, err := a.versionManagementEnabled(tt.cluster)
			if tt.expectError {
				assert.Error(t, err)
			}
			assert.Equal(t, tt.expectResult, got)
		})
	}
}

func Test_validateAgentSchedulingCustomizationPodDisruptionBudget(t *testing.T) {
	tests := []struct {
		name           string
		pdb            *v3.PodDisruptionBudgetSpec
		oldPDB         *v3.PodDisruptionBudgetSpec
		featureEnabled bool
		shouldSucceed  bool
	}{
		{
			name:           "no scheduling customization - feature enabled",
			pdb:            nil, // results in empty cluster without scheduling customization
			shouldSucceed:  true,
			featureEnabled: true,
		},
		{
			name:           "no scheduling customization - feature disabled",
			oldPDB:         nil,
			pdb:            nil,
			shouldSucceed:  true,
			featureEnabled: false,
		},
		{
			name:           "invalid PDB configuration - negative min available integer",
			shouldSucceed:  false,
			featureEnabled: true,
			pdb: &v3.PodDisruptionBudgetSpec{
				MinAvailable: "-1",
			},
		},
		{
			name:           "invalid PDB configuration - negative max unavailable integer",
			shouldSucceed:  false,
			featureEnabled: true,
			pdb: &v3.PodDisruptionBudgetSpec{
				MaxUnavailable: "-1",
			},
		},
		{
			name:           "invalid PDB configuration - both fields set",
			shouldSucceed:  false,
			featureEnabled: true,
			pdb: &v3.PodDisruptionBudgetSpec{
				MinAvailable:   "1",
				MaxUnavailable: "1",
			},
		},
		{
			name:           "invalid PDB configuration - string passed to max unavailable",
			shouldSucceed:  false,
			featureEnabled: true,
			pdb: &v3.PodDisruptionBudgetSpec{
				MaxUnavailable: "five",
			},
		},
		{
			name:           "invalid PDB configuration - string passed to min available",
			shouldSucceed:  false,
			featureEnabled: true,
			pdb: &v3.PodDisruptionBudgetSpec{
				MinAvailable: "five",
			},
		},
		{
			name:           "invalid PDB configuration - string with invalid percentage number set for min available",
			shouldSucceed:  false,
			featureEnabled: true,
			pdb: &v3.PodDisruptionBudgetSpec{
				MinAvailable: "5.5%",
			},
		},
		{
			name:           "invalid PDB configuration - string with invalid percentage number set for max unavailable",
			shouldSucceed:  false,
			featureEnabled: true,
			pdb: &v3.PodDisruptionBudgetSpec{
				MaxUnavailable: "5.5%",
			},
		},
		{
			name:           "invalid PDB configuration - both set to zero",
			shouldSucceed:  false,
			featureEnabled: true,
			pdb: &v3.PodDisruptionBudgetSpec{
				MinAvailable:   "0",
				MaxUnavailable: "0",
			},
		},
		{
			name:           "valid PDB configuration - max unavailable set to integer",
			shouldSucceed:  true,
			featureEnabled: true,
			pdb: &v3.PodDisruptionBudgetSpec{
				MaxUnavailable: "1",
			},
		},
		{
			name:           "valid PDB configuration - min available set to integer",
			shouldSucceed:  true,
			featureEnabled: true,
			pdb: &v3.PodDisruptionBudgetSpec{
				MinAvailable: "1",
			},
		},
		{
			name:           "valid PDB configuration - min available set to integer",
			shouldSucceed:  true,
			featureEnabled: true,
			pdb: &v3.PodDisruptionBudgetSpec{
				MinAvailable:   "1",
				MaxUnavailable: "0",
			},
		},
		{
			name:           "valid PDB configuration - max unavailable set to integer",
			shouldSucceed:  true,
			featureEnabled: true,
			pdb: &v3.PodDisruptionBudgetSpec{
				MinAvailable:   "0",
				MaxUnavailable: "1",
			},
		},
		{
			name:           "valid PDB configuration - max unavailable set to percentage",
			shouldSucceed:  true,
			featureEnabled: true,
			pdb: &v3.PodDisruptionBudgetSpec{
				MaxUnavailable: "50%",
			},
		},
		{
			name:           "valid PDB configuration - min available set to percentage",
			shouldSucceed:  true,
			featureEnabled: true,
			pdb: &v3.PodDisruptionBudgetSpec{
				MinAvailable: "50%",
			},
		},
		{
			name:           "valid PDB configuration - updating from percentage to int",
			shouldSucceed:  true,
			featureEnabled: true,
			oldPDB: &v3.PodDisruptionBudgetSpec{
				MinAvailable: "50%",
			},
			pdb: &v3.PodDisruptionBudgetSpec{
				MinAvailable: "1",
			},
		},
		{
			name:           "invalid PDB reconfiguration - feature is disabled",
			shouldSucceed:  false,
			featureEnabled: false,
			oldPDB: &v3.PodDisruptionBudgetSpec{
				MinAvailable: "50%",
			},
			pdb: &v3.PodDisruptionBudgetSpec{
				MinAvailable: "1",
			},
		},
		{
			name:           "invalid PDB creation - feature is disabled",
			shouldSucceed:  false,
			featureEnabled: false,
			oldPDB:         nil,
			pdb: &v3.PodDisruptionBudgetSpec{
				MinAvailable: "1",
			},
		},
		{
			name:           "valid PDB reconfiguration - field is removed while feature is disabled",
			shouldSucceed:  true,
			featureEnabled: false,
			oldPDB: &v3.PodDisruptionBudgetSpec{
				MinAvailable: "50%",
			},
			pdb: nil,
		},
		{
			name:           "valid update - field is unchanged while feature is disabled",
			shouldSucceed:  true,
			featureEnabled: false,
			oldPDB: &v3.PodDisruptionBudgetSpec{
				MinAvailable: "50%",
			},
			pdb: &v3.PodDisruptionBudgetSpec{
				MinAvailable: "50%",
			},
		},
	}

	t.Parallel()
	for _, agentType := range common.AllAgentTypes {
		for _, tt := range tests {
			t.Run(fmt.Sprintf("%s/%s", agentType, tt.name), func(t *testing.T) {
				ctrl := gomock.NewController(t)
				a := admitter{
					featureCache: createMockFeatureCache(ctrl, common.SchedulingCustomizationFeatureName, tt.featureEnabled),
				}

				var oldCluster, newCluster *v3.Cluster
				oldCluster = newClusterWithPDB(tt.oldPDB, agentType)
				newCluster = newClusterWithPDB(tt.pdb, agentType)

				response, err := a.validatePodDisruptionBudget(oldCluster, newCluster, admissionv1.Create)
				assert.Equal(t, tt.shouldSucceed, response.Allowed)
				assert.NoError(t, err)

				response, err = a.validatePodDisruptionBudget(oldCluster, newCluster, admissionv1.Update)
				assert.Equal(t, tt.shouldSucceed, response.Allowed)
				assert.Nil(t, err)
				assert.NoError(t, err)
			})
		}
	}
}

func newClusterWithPDB(pdb *v3.PodDisruptionBudgetSpec, agentType common.AgentType) *v3.Cluster {
	c := &v3.Cluster{}
	if pdb == nil {
		return c
	}
	switch agentType {
	case common.AgentTypeCluster:
		c.Spec = v3.ClusterSpec{
			ClusterSpecBase: v3.ClusterSpecBase{
				ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
					SchedulingCustomization: &v3.AgentSchedulingCustomization{
						PodDisruptionBudget: pdb,
					},
				},
			},
		}
	case common.AgentTypeFleet:
		c.Spec = v3.ClusterSpec{
			ClusterSpecBase: v3.ClusterSpecBase{
				FleetAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
					SchedulingCustomization: &v3.AgentSchedulingCustomization{
						PodDisruptionBudget: pdb,
					},
				},
			},
		}
	}
	return c
}

func Test_validateAgentSchedulingCustomizationPriorityClass(t *testing.T) {
	preemptionNever := k8sv1.PreemptionPolicy("Never")
	preemptionInvalid := k8sv1.PreemptionPolicy("rancher")

	tests := []struct {
		name           string
		pc             *v3.PriorityClassSpec
		oldPC          *v3.PriorityClassSpec
		featureEnabled bool
		shouldSucceed  bool
	}{
		{
			name:           "empty priority class - feature enabled",
			pc:             nil,
			shouldSucceed:  true,
			featureEnabled: true,
		},
		{
			name:           "empty priority class - feature disabled",
			pc:             nil,
			shouldSucceed:  true,
			featureEnabled: true,
		},
		{
			name:           "valid priority class with default preemption",
			shouldSucceed:  true,
			featureEnabled: true,
			pc: &v3.PriorityClassSpec{
				Value: 123456,
			},
		},
		{
			name:           "valid priority class with custom preemption",
			shouldSucceed:  true,
			featureEnabled: true,
			pc: &v3.PriorityClassSpec{
				Value:            123456,
				PreemptionPolicy: &preemptionNever,
			},
		},
		{
			name:           "invalid priority class - value too large",
			shouldSucceed:  false,
			featureEnabled: true,
			pc: &v3.PriorityClassSpec{
				Value: 1234567891234567890,
			},
		},
		{
			name:           "invalid priority class - value too small",
			shouldSucceed:  false,
			featureEnabled: true,
			pc: &v3.PriorityClassSpec{
				Value: -1234567891234567890,
			},
		},
		{
			name:           "invalid priority class - preemption value invalid",
			shouldSucceed:  false,
			featureEnabled: true,
			pc: &v3.PriorityClassSpec{
				Value:            24321,
				PreemptionPolicy: &preemptionInvalid,
			},
		},
		{
			name:           "invalid priority class - feature is disabled",
			shouldSucceed:  false,
			featureEnabled: false,
			pc: &v3.PriorityClassSpec{
				Value:            24321,
				PreemptionPolicy: &preemptionInvalid,
			},
		},
		{
			name:           "invalid update attempt - feature is disabled",
			shouldSucceed:  false,
			featureEnabled: false,
			oldPC: &v3.PriorityClassSpec{
				Value: 1234,
			},
			pc: &v3.PriorityClassSpec{
				Value: 4321,
			},
		},
		{
			name:           "valid update attempt - feature is enabled",
			shouldSucceed:  false,
			featureEnabled: false,
			oldPC: &v3.PriorityClassSpec{
				Value: 1234,
			},
			pc: &v3.PriorityClassSpec{
				Value: 4321,
			},
		},
		{
			name:           "valid update attempt - feature is disabled, but fields are unchanged",
			shouldSucceed:  true,
			featureEnabled: false,
			oldPC: &v3.PriorityClassSpec{
				Value: 1234,
			},
			pc: &v3.PriorityClassSpec{
				Value: 1234,
			},
		},
		{
			name:           "valid update attempt - field is removed while feature is disabled",
			shouldSucceed:  true,
			featureEnabled: false,
			oldPC: &v3.PriorityClassSpec{
				Value: 1234,
			},
			pc: nil,
		},
	}

	t.Parallel()
	for _, agentType := range common.AllAgentTypes {
		for _, tt := range tests {
			t.Run(fmt.Sprintf("%s/%s", agentType, tt.name), func(t *testing.T) {
				ctrl := gomock.NewController(t)
				a := admitter{
					featureCache: createMockFeatureCache(ctrl, common.SchedulingCustomizationFeatureName, tt.featureEnabled),
				}

				oldCluster := newClusterWithPC(tt.oldPC, agentType)
				newCluster := newClusterWithPC(tt.pc, agentType)

				response, err := a.validatePriorityClass(oldCluster, newCluster, admissionv1.Create)
				assert.Equal(t, tt.shouldSucceed, response.Allowed)
				assert.NoError(t, err)

				response, err = a.validatePriorityClass(oldCluster, newCluster, admissionv1.Update)
				assert.Equal(t, tt.shouldSucceed, response.Allowed)
				assert.Nil(t, err)
				assert.NoError(t, err)
			})
		}
	}
}

func newClusterWithPC(pc *v3.PriorityClassSpec, agentType common.AgentType) *v3.Cluster {
	c := &v3.Cluster{}
	if pc == nil {
		return c
	}
	switch agentType {
	case common.AgentTypeCluster:
		c.Spec = v3.ClusterSpec{
			ClusterSpecBase: v3.ClusterSpecBase{
				ClusterAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
					SchedulingCustomization: &v3.AgentSchedulingCustomization{
						PriorityClass: pc,
					},
				},
			},
		}
	case common.AgentTypeFleet:
		c.Spec = v3.ClusterSpec{
			ClusterSpecBase: v3.ClusterSpecBase{
				FleetAgentDeploymentCustomization: &v3.AgentDeploymentCustomization{
					SchedulingCustomization: &v3.AgentSchedulingCustomization{
						PriorityClass: pc,
					},
				},
			},
		}
	}
	return c
}

func createMockFeatureCache(ctrl *gomock.Controller, featureName string, enabled bool) *fake.MockNonNamespacedCacheInterface[*v3.Feature] {
	featureCache := fake.NewMockNonNamespacedCacheInterface[*v3.Feature](ctrl)
	featureCache.EXPECT().Get(featureName).DoAndReturn(func(string) (*v3.Feature, error) {
		return &v3.Feature{
			Spec: v3.FeatureSpec{
				Value: &enabled,
			},
		}, nil
	}).AnyTimes()
	return featureCache
}
