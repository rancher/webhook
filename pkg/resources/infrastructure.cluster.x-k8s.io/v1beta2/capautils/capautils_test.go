package capautils

import (
	"context"
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
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// mockSAR implements authorizationv1.SubjectAccessReviewInterface for testing.
type mockSAR struct {
	allowed bool
	err     error
	calls   int
}

func (m *mockSAR) Create(_ context.Context, _ *authorizationv1.SubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SubjectAccessReview, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
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

func makeRequest(username string) *admission.Request {
	return &admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			UserInfo: authenticationv1.UserInfo{Username: username},
		},
	}
}

func TestIsMirroredCloudCredential(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		cacheErr   error
		wantResult bool
		wantErr    bool
	}{
		{
			name:       "secret found — mirrored credential",
			cacheErr:   nil,
			wantResult: true,
		},
		{
			name:       "secret not found — user-managed",
			cacheErr:   apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "my-secret"),
			wantResult: false,
		},
		{
			name:     "cache error — propagated",
			cacheErr: fmt.Errorf("etcd unavailable"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var secret *corev1.Secret
			if tt.cacheErr == nil {
				secret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "my-secret", Namespace: RancherCredentialsNamespace}}
			}
			cache := &mockSecretCache{secret: secret, err: tt.cacheErr}

			got, err := IsMirroredCloudCredential("my-secret", cache)
			if (err != nil) != tt.wantErr {
				t.Fatalf("IsMirroredCloudCredential() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.wantResult {
				t.Errorf("IsMirroredCloudCredential() = %v, want %v", got, tt.wantResult)
			}
		})
	}
}

func TestCheckSecretAccess(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		secretName  string
		sarAllowed  bool
		sarErr      error
		wantAllowed bool
		wantErr     bool
		wantCalls   int
	}{
		{
			name:        "access granted",
			secretName:  "my-secret",
			sarAllowed:  true,
			wantAllowed: true,
			wantCalls:   1,
		},
		{
			name:        "access denied",
			secretName:  "my-secret",
			sarAllowed:  false,
			wantAllowed: false,
			wantCalls:   1,
		},
		{
			name:       "SAR call fails",
			secretName: "my-secret",
			sarErr:     fmt.Errorf("connection refused"),
			wantErr:    true,
			wantCalls:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sar := &mockSAR{allowed: tt.sarAllowed, err: tt.sarErr}
			resp, err := CheckSecretAccess(makeRequest("test-user"), tt.secretName, sar)

			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckSecretAccess() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if resp.Allowed != tt.wantAllowed {
					t.Errorf("Allowed=%v, want %v (result: %+v)", resp.Allowed, tt.wantAllowed, resp.Result)
				}
			}
			if sar.calls != tt.wantCalls {
				t.Errorf("SAR calls=%d, want %d", sar.calls, tt.wantCalls)
			}
		})
	}
}
