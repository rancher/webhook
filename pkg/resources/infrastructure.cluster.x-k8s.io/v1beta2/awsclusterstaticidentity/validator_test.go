package awsclusterstaticidentity

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

// mockSAR implements k8s.io/client-go/kubernetes/typed/authorization/v1.SubjectAccessReviewInterface for testing.
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

// makeIdentity builds an AWSClusterStaticIdentity with the given secretRef.
func makeIdentity(secretRef string) *infrav1.AWSClusterStaticIdentity {
	return &infrav1.AWSClusterStaticIdentity{
		ObjectMeta: metav1.ObjectMeta{Name: "my-identity"},
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

func makeRequest(t *testing.T, op admissionv1.Operation, newObj, oldObj *infrav1.AWSClusterStaticIdentity) *admission.Request {
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

func TestAWSClusterStaticIdentityValidator_Admit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		operation    admissionv1.Operation
		newObj       *infrav1.AWSClusterStaticIdentity
		oldObj       *infrav1.AWSClusterStaticIdentity
		secretCache  *mockSecretCache
		sarAllowed   bool
		wantAllowed  bool
		wantErr      bool
		wantSARCalls int
	}{
		// --- Empty secretRef: always allowed regardless of cache ---
		{
			name:         "CREATE empty secretRef, allowed without cache lookup or SAR",
			operation:    admissionv1.Create,
			newObj:       makeIdentity(""),
			secretCache:  makeAbsentSecretCache(),
			wantAllowed:  true,
			wantSARCalls: 0,
		},

		// --- Secret NOT in cattle-global-data: user-managed, always allowed ---
		{
			name:         "CREATE secretRef set, no mirrored secret, user-managed, allowed without SAR",
			operation:    admissionv1.Create,
			newObj:       makeIdentity("my-secret"),
			secretCache:  makeAbsentSecretCache(),
			wantAllowed:  true,
			wantSARCalls: 0,
		},
		{
			name:         "UPDATE secretRef changed, no mirrored secret, allowed without SAR",
			operation:    admissionv1.Update,
			newObj:       makeIdentity("new-secret"),
			oldObj:       makeIdentity("old-secret"),
			secretCache:  makeAbsentSecretCache(),
			wantAllowed:  true,
			wantSARCalls: 0,
		},

		// --- Mirrored secret found: SAR enforced ---
		{
			name:         "CREATE mirrored secret, user has access",
			operation:    admissionv1.Create,
			newObj:       makeIdentity("my-secret"),
			secretCache:  makeMirroredSecretCache("my-secret"),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1,
		},
		{
			name:         "CREATE mirrored secret, user lacks access",
			operation:    admissionv1.Create,
			newObj:       makeIdentity("my-secret"),
			secretCache:  makeMirroredSecretCache("my-secret"),
			sarAllowed:   false,
			wantAllowed:  false,
			wantSARCalls: 1,
		},

		// --- UPDATE secretRef unchanged: SAR still enforced ---
		{
			name:         "UPDATE secretRef unchanged, mirrored secret, SAR still enforced, user has access",
			operation:    admissionv1.Update,
			newObj:       makeIdentity("same-secret"),
			oldObj:       makeIdentity("same-secret"),
			secretCache:  makeMirroredSecretCache("same-secret"),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1,
		},
		{
			name:         "UPDATE secretRef unchanged, no mirrored secret, user-managed, allowed",
			operation:    admissionv1.Update,
			newObj:       makeIdentity("same-secret"),
			oldObj:       makeIdentity("same-secret"),
			secretCache:  makeAbsentSecretCache(),
			wantAllowed:  true,
			wantSARCalls: 0,
		},

		// --- UPDATE secretRef changed, mirrored secret ---
		{
			name:         "UPDATE secretRef changed, mirrored secret, user has access",
			operation:    admissionv1.Update,
			newObj:       makeIdentity("new-secret"),
			oldObj:       makeIdentity("old-secret"),
			secretCache:  makeMirroredSecretCache("new-secret"),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1,
		},
		{
			name:         "UPDATE secretRef changed, mirrored secret, user lacks access",
			operation:    admissionv1.Update,
			newObj:       makeIdentity("new-secret"),
			oldObj:       makeIdentity("old-secret"),
			secretCache:  makeMirroredSecretCache("new-secret"),
			sarAllowed:   false,
			wantAllowed:  false,
			wantSARCalls: 1,
		},

		// --- Cache error: fail closed ---
		{
			name:         "CREATE cache error, fail closed",
			operation:    admissionv1.Create,
			newObj:       makeIdentity("my-secret"),
			secretCache:  makeErrorSecretCache(),
			wantErr:      true,
			wantSARCalls: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sar := &mockSAR{allowed: tt.sarAllowed}
			v := NewValidator(tt.secretCache, sar)

			resp, err := v.Admit(makeRequest(t, tt.operation, tt.newObj, tt.oldObj))
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
