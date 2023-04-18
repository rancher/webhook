package cluster

import (
	"context"
	"encoding/json"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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

type testCase struct {
	oldCluster     v3.Cluster
	newCluster     v3.Cluster
	operation      admissionv1.Operation
	expectAllowed  bool
	expectedReason metav1.StatusReason
}

func TestAdmit(t *testing.T) {
	for name, tc := range map[string]testCase{
		"Create": {
			operation:     admissionv1.Create,
			expectAllowed: true,
		},
		"UpdateWithUnsetFleetWorkspaceName": {
			oldCluster:     v3.Cluster{Spec: v3.ClusterSpec{FleetWorkspaceName: "fleet-default"}},
			operation:      admissionv1.Update,
			expectAllowed:  false,
			expectedReason: metav1.StatusReasonInvalid,
		},
		"UpdateWithNewFleetWorkspaceName": {
			oldCluster:    v3.Cluster{Spec: v3.ClusterSpec{FleetWorkspaceName: "fleet-default"}},
			newCluster:    v3.Cluster{Spec: v3.ClusterSpec{FleetWorkspaceName: "new"}},
			operation:     admissionv1.Update,
			expectAllowed: true,
		},
		"UpdateWithUnchangedFleetWorkspaceName": {
			oldCluster:    v3.Cluster{Spec: v3.ClusterSpec{FleetWorkspaceName: "fleet-default"}},
			newCluster:    v3.Cluster{Spec: v3.ClusterSpec{FleetWorkspaceName: "fleet-default"}},
			operation:     admissionv1.Update,
			expectAllowed: true,
		},
		"Delete": {
			oldCluster:    v3.Cluster{Spec: v3.ClusterSpec{FleetWorkspaceName: "fleet-default"}},
			operation:     admissionv1.Delete,
			expectAllowed: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			v := &Validator{
				sar: &mockReviewer{},
			}

			oldClusterBytes, err := json.Marshal(tc.oldCluster)
			assert.NoError(t, err)
			newClusterBytes, err := json.Marshal(tc.newCluster)
			assert.NoError(t, err)

			res, err := v.Admit(&admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Object: runtime.RawExtension{
						Raw: newClusterBytes,
					},
					OldObject: runtime.RawExtension{
						Raw: oldClusterBytes,
					},
					Operation: tc.operation,
				},
			})
			assert.NoError(t, err)
			assert.Equal(t, tc.expectAllowed, res.Allowed)

			if !tc.expectAllowed {
				assert.Equal(t, tc.expectedReason, res.Result.Reason)
			}
		})
	}
}
