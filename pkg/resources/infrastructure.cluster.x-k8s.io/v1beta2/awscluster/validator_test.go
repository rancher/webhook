package awscluster

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/wrangler/v3/pkg/generic"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
)

// mockSAR implements k8s.io/client-go/kubernetes/typed/authorization/v1.SubjectAccessReviewInterface.
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

// mockSecretCache implements corev1controller.SecretCache for testing.
type mockSecretCache struct {
	secret *corev1.Secret
	err    error
}

func (m *mockSecretCache) Get(_, _ string) (*corev1.Secret, error) {
	return m.secret, m.err
}

func (m *mockSecretCache) List(_ string, _ labels.Selector) ([]*corev1.Secret, error) {
	panic("not implemented")
}

func (m *mockSecretCache) AddIndexer(_ string, _ generic.Indexer[*corev1.Secret]) {
	panic("not implemented")
}

func (m *mockSecretCache) GetByIndex(_, _ string) ([]*corev1.Secret, error) {
	panic("not implemented")
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

// makeStaticIdentity builds an AWSClusterStaticIdentity with the given secretRef.
func makeStaticIdentity(secretRef string) *infrav1.AWSClusterStaticIdentity {
	return &infrav1.AWSClusterStaticIdentity{
		ObjectMeta: metav1.ObjectMeta{Name: "my-static-id"},
		Spec: infrav1.AWSClusterStaticIdentitySpec{
			SecretRef: secretRef,
		},
	}
}

// makeMirroredSecretCache returns a cache that reports the named secret as
// present in cattle-global-data (mirrored Rancher Cloud Credential).
func makeMirroredSecretCache(secretName string) *mockSecretCache {
	return &mockSecretCache{
		secret: &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: "cattle-global-data"}},
	}
}

// makeAbsentSecretCache returns a cache that reports no secret in cattle-global-data.
func makeAbsentSecretCache() *mockSecretCache {
	return &mockSecretCache{
		err: apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, ""),
	}
}

// makeErrorSecretCache returns a cache that returns a transient error.
func makeErrorSecretCache() *mockSecretCache {
	return &mockSecretCache{err: fmt.Errorf("etcd unavailable")}
}

func makeRequest(t *testing.T, op admissionv1.Operation, newObj, oldObj *infrav1.AWSCluster) *admission.Request {
	t.Helper()
	req := &admission.Request{
		Context: context.Background(),
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
	t.Parallel()
	tests := []struct {
		name         string
		operation    admissionv1.Operation
		newCluster   *infrav1.AWSCluster
		oldCluster   *infrav1.AWSCluster
		dynamicObj   runtime.Object
		dynamicErr   error
		secretCache  *mockSecretCache
		sarAllowed   bool
		wantAllowed  bool
		wantErr      bool
		wantSARCalls int
	}{
		// --- No identityRef or non-static kind: always allowed ---
		{
			name:         "CREATE no identityRef, allowed",
			operation:    admissionv1.Create,
			newCluster:   makeCluster("", ""),
			secretCache:  makeAbsentSecretCache(),
			wantAllowed:  true,
			wantSARCalls: 0,
		},
		{
			name:         "CREATE identityRef kind=AWSClusterRoleIdentity, allowed",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterRoleIdentityKind, "my-role-id"),
			secretCache:  makeAbsentSecretCache(),
			wantAllowed:  true,
			wantSARCalls: 0,
		},
		{
			name:         "CREATE identityRef kind=AWSClusterControllerIdentity, allowed",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ControllerIdentityKind, "default"),
			secretCache:  makeAbsentSecretCache(),
			wantAllowed:  true,
			wantSARCalls: 0,
		},

		// --- Dynamic lookup errors ---
		{
			name:         "CREATE identity not found, BadRequest",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "missing-id"),
			dynamicErr:   apierrors.NewNotFound(schema.GroupResource{Resource: "awsclusterstaticidentities"}, "missing-id"),
			secretCache:  makeAbsentSecretCache(),
			wantAllowed:  false,
			wantSARCalls: 0,
		},
		{
			name:         "CREATE identity lookup generic error, BadRequest",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicErr:   fmt.Errorf("no matches for kind AWSClusterStaticIdentity"),
			secretCache:  makeAbsentSecretCache(),
			wantAllowed:  false,
			wantSARCalls: 0,
		},

		// --- Identity found, empty secretRef: always allowed ---
		{
			name:         "CREATE identity found, empty secretRef, allowed without SAR",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity(""),
			secretCache:  makeAbsentSecretCache(),
			wantAllowed:  true,
			wantSARCalls: 0,
		},

		// --- Secret NOT in cattle-global-data: user-managed, always allowed ---
		{
			name:         "CREATE identity found, secretRef set, no mirrored secret, user-managed, allowed",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCache:  makeAbsentSecretCache(),
			wantAllowed:  true,
			wantSARCalls: 0,
		},

		// --- Mirrored secret found: SAR enforced ---
		{
			name:         "CREATE mirrored secret, user has access",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCache:  makeMirroredSecretCache("my-secret"),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1,
		},
		{
			name:         "CREATE mirrored secret, user lacks access",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCache:  makeMirroredSecretCache("my-secret"),
			sarAllowed:   false,
			wantAllowed:  false,
			wantSARCalls: 1,
		},

		// --- Cache error: fail closed ---
		{
			name:         "CREATE cache error, fail closed",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCache:  makeErrorSecretCache(),
			wantErr:      true,
			wantSARCalls: 0,
		},

		// --- UPDATE: identity always re-fetched (no identityRef-unchanged skip) ---
		{
			name:         "UPDATE identityRef unchanged, identity re-fetched, mirrored secret, SAR enforced",
			operation:    admissionv1.Update,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "same-id"),
			oldCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "same-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCache:  makeMirroredSecretCache("my-secret"),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1,
		},
		{
			name:         "UPDATE identityRef unchanged, identity re-fetched, no mirrored secret, allowed",
			operation:    admissionv1.Update,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "same-id"),
			oldCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "same-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCache:  makeAbsentSecretCache(),
			wantAllowed:  true,
			wantSARCalls: 0,
		},
		{
			name:         "UPDATE identityRef name changed, mirrored secret, user has access",
			operation:    admissionv1.Update,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "new-id"),
			oldCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "old-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCache:  makeMirroredSecretCache("my-secret"),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1,
		},
		{
			name:         "UPDATE identityRef kind changed to static, mirrored secret, user lacks access",
			operation:    admissionv1.Update,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-id"),
			oldCluster:   makeCluster(infrav1.ClusterRoleIdentityKind, "my-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCache:  makeMirroredSecretCache("my-secret"),
			sarAllowed:   false,
			wantAllowed:  false,
			wantSARCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sar := &mockSAR{allowed: tt.sarAllowed}
			dyn := &mockDynamic{obj: tt.dynamicObj, err: tt.dynamicErr}
			v := NewValidator(dyn, tt.secretCache, sar)

			resp, err := v.Admit(makeRequest(t, tt.operation, tt.newCluster, tt.oldCluster))
			if (err != nil) != tt.wantErr {
				t.Fatalf("Admit() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				return
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
