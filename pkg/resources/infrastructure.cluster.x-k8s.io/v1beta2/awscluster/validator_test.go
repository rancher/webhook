package awscluster

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
)

// mockSAR implements authorizationv1client.SubjectAccessReviewInterface.
type mockSAR struct {
	allowed bool
	calls   int
}

func (m *mockSAR) Create(_ context.Context, _ *authorizationv1.SubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SubjectAccessReview, error) {
	m.calls++
	return &authorizationv1.SubjectAccessReview{
		Status: authorizationv1.SubjectAccessReviewStatus{Allowed: m.allowed},
	}, nil
}

// mockDynamic implements dynamicGetter for testing.
type mockDynamic struct {
	obj runtime.Object
	err error
}

func (m *mockDynamic) Get(_ schema.GroupVersionKind, _, _ string) (runtime.Object, error) {
	return m.obj, m.err
}

func mustMarshal(t *testing.T, obj interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("mustMarshal: %v", err)
	}
	return b
}

func makeCluster(identityKind infrav1.AWSIdentityKind, identityName string) *infrav1.AWSCluster {
	cluster := &infrav1.AWSCluster{
		ObjectMeta: metav1.ObjectMeta{Name: "my-cluster", Namespace: "default"},
	}
	if identityKind != "" || identityName != "" {
		cluster.Spec.IdentityRef = &infrav1.AWSIdentityReference{
			Kind: identityKind,
			Name: identityName,
		}
	}
	return cluster
}

func makeStaticIdentity(secretRef string) *infrav1.AWSClusterStaticIdentity {
	return &infrav1.AWSClusterStaticIdentity{
		ObjectMeta: metav1.ObjectMeta{Name: "my-static-id"},
		Spec: infrav1.AWSClusterStaticIdentitySpec{
			SecretRef: secretRef,
		},
	}
}

func makeRequest(t *testing.T, op admissionv1.Operation, newObj, oldObj *infrav1.AWSCluster) *admission.Request {
	t.Helper()
	req := &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: op,
			Object:    runtime.RawExtension{Raw: mustMarshal(t, newObj)},
			UserInfo:  authenticationv1.UserInfo{Username: "test-user"},
		},
	}
	if oldObj != nil {
		req.OldObject = runtime.RawExtension{Raw: mustMarshal(t, oldObj)}
	}
	return req
}

func TestAWSClusterValidator_Admit(t *testing.T) {
	tests := []struct {
		name         string
		operation    admissionv1.Operation
		newCluster   *infrav1.AWSCluster
		oldCluster   *infrav1.AWSCluster
		dynamicObj   runtime.Object
		dynamicErr   error
		sarAllowed   bool
		wantAllowed  bool
		wantSARCalls int
	}{
		{
			name:         "CREATE no identityRef, allowed without SAR",
			operation:    admissionv1.Create,
			newCluster:   makeCluster("", ""),
			wantAllowed:  true,
			wantSARCalls: 0,
		},
		{
			name:         "CREATE identityRef kind=AWSClusterRoleIdentity, allowed without SAR",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterRoleIdentityKind, "my-role-id"),
			wantAllowed:  true,
			wantSARCalls: 0,
		},
		{
			name:         "CREATE identityRef kind=AWSClusterControllerIdentity, allowed without SAR",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ControllerIdentityKind, "default"),
			wantAllowed:  true,
			wantSARCalls: 0,
		},
		{
			name:         "CREATE identityRef kind=AWSClusterStaticIdentity, user has access",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1,
		},
		{
			name:         "CREATE identityRef kind=AWSClusterStaticIdentity, user lacks access",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			sarAllowed:   false,
			wantAllowed:  false,
			wantSARCalls: 1,
		},
		{
			name:         "CREATE identity not found, BadRequest",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "missing-id"),
			dynamicErr:   apierrors.NewNotFound(schema.GroupResource{Resource: "awsclusterstaticidentities"}, "missing-id"),
			wantAllowed:  false,
			wantSARCalls: 0,
		},
		{
			name:         "CREATE identity lookup generic error, BadRequest",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicErr:   fmt.Errorf("no matches for kind AWSClusterStaticIdentity"),
			wantAllowed:  false,
			wantSARCalls: 0,
		},
		{
			name:         "CREATE identity found, empty secretRef, allowed without SAR",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity(""),
			wantAllowed:  true,
			wantSARCalls: 0,
		},
		{
			name:         "UPDATE identityRef unchanged, allowed without dynamic lookup or SAR",
			operation:    admissionv1.Update,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "same-id"),
			oldCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "same-id"),
			dynamicObj:   nil, // must NOT be called
			wantAllowed:  true,
			wantSARCalls: 0,
		},
		{
			name:         "UPDATE identityRef name changed, SAR performed, allowed",
			operation:    admissionv1.Update,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "new-id"),
			oldCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "old-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1,
		},
		{
			name: "UPDATE identityRef kind changed to ClusterStaticIdentityKind, " +
				"non-existing AWSClusterStaticIdentity, SAR performed, denied",
			operation:    admissionv1.Update,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-id"),
			oldCluster:   makeCluster(infrav1.ClusterRoleIdentityKind, "my-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			sarAllowed:   false,
			wantAllowed:  false,
			wantSARCalls: 1,
		},
	}

	t.Parallel()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sar := &mockSAR{allowed: tt.sarAllowed}
			dyn := &mockDynamic{obj: tt.dynamicObj, err: tt.dynamicErr}
			v := NewValidator(dyn, sar)

			resp, err := v.Admit(makeRequest(t, tt.operation, tt.newCluster, tt.oldCluster))
			if err != nil {
				t.Fatalf("Admit returned error: %v", err)
			}
			if resp.Allowed != tt.wantAllowed {
				t.Errorf("Allowed=%v, want %v (result: %+v)", resp.Allowed, tt.wantAllowed, resp.Result)
			}
			if sar.calls != tt.wantSARCalls {
				t.Errorf("SAR calls=%d, want %d", sar.calls, tt.wantSARCalls)
			}
		})
	}
}
