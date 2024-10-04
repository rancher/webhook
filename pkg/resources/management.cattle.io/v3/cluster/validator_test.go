package cluster

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/common"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{
				admitter: admitter{
					sar:       &mockReviewer{},
					userCache: userCache,
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
