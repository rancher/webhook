package capautils

import (
	"context"
	"fmt"
	"testing"
	"time"

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
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// ---------------------------------------------------------------------------
// mockSAR
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// mockSecretCache — implements generic.CacheInterface[*corev1.Secret]
// ---------------------------------------------------------------------------

type mockSecretCache struct {
	secret *corev1.Secret
	err    error
}

func (m *mockSecretCache) Get(_, _ string) (*corev1.Secret, error) { return m.secret, m.err }
func (m *mockSecretCache) List(_ string, _ labels.Selector) ([]*corev1.Secret, error) {
	panic("not implemented")
}
func (m *mockSecretCache) AddIndexer(_ string, _ generic.Indexer[*corev1.Secret]) {
	panic("not implemented")
}
func (m *mockSecretCache) GetByIndex(_, _ string) ([]*corev1.Secret, error) {
	panic("not implemented")
}

// ---------------------------------------------------------------------------
// mockSecretController — implements corev1controller.SecretController
// ---------------------------------------------------------------------------

type mockSecretController struct {
	cacheObj *mockSecretCache
	// apiCall is invoked for the fallback Get path; apiCalls counts invocations.
	apiSecret *corev1.Secret
	apiErr    error
	apiCalls  int
}

// Cache (exercised by IsMirroredCloudCredential primary path)
func (m *mockSecretController) Cache() generic.CacheInterface[*corev1.Secret] { return m.cacheObj }

// Get (exercised by IsMirroredCloudCredential fallback path)
func (m *mockSecretController) Get(_, _ string, _ metav1.GetOptions) (*corev1.Secret, error) {
	m.apiCalls++
	return m.apiSecret, m.apiErr
}

// ---- ClientInterface stubs ----
func (m *mockSecretController) Create(_ *corev1.Secret) (*corev1.Secret, error) {
	panic("not implemented")
}
func (m *mockSecretController) Update(_ *corev1.Secret) (*corev1.Secret, error) {
	panic("not implemented")
}
func (m *mockSecretController) UpdateStatus(_ *corev1.Secret) (*corev1.Secret, error) {
	panic("not implemented")
}
func (m *mockSecretController) Delete(_, _ string, _ *metav1.DeleteOptions) error {
	panic("not implemented")
}
func (m *mockSecretController) List(_ string, _ metav1.ListOptions) (*corev1.SecretList, error) {
	panic("not implemented")
}
func (m *mockSecretController) Watch(_ string, _ metav1.ListOptions) (watch.Interface, error) {
	panic("not implemented")
}
func (m *mockSecretController) Patch(_, _ string, _ types.PatchType, _ []byte, _ ...string) (*corev1.Secret, error) {
	panic("not implemented")
}
func (m *mockSecretController) WithImpersonation(_ rest.ImpersonationConfig) (generic.ClientInterface[*corev1.Secret, *corev1.SecretList], error) {
	panic("not implemented")
}
func (m *mockSecretController) DeleteCollection(_ string, _ metav1.DeleteOptions, _ metav1.ListOptions) error {
	panic("not implemented")
}

// ---- ControllerMeta stubs ----
func (m *mockSecretController) Informer() cache.SharedIndexInformer { panic("not implemented") }
func (m *mockSecretController) GroupVersionKind() schema.GroupVersionKind {
	panic("not implemented")
}
func (m *mockSecretController) AddGenericHandler(_ context.Context, _ string, _ generic.Handler) {
	panic("not implemented")
}
func (m *mockSecretController) AddGenericRemoveHandler(_ context.Context, _ string, _ generic.Handler) {
	panic("not implemented")
}
func (m *mockSecretController) Updater() generic.Updater { panic("not implemented") }

// ---- ControllerInterface stubs ----
func (m *mockSecretController) OnChange(_ context.Context, _ string, _ generic.ObjectHandler[*corev1.Secret]) {
	panic("not implemented")
}
func (m *mockSecretController) OnRemove(_ context.Context, _ string, _ generic.ObjectHandler[*corev1.Secret]) {
	panic("not implemented")
}
func (m *mockSecretController) Enqueue(_, _ string)                       { panic("not implemented") }
func (m *mockSecretController) EnqueueAfter(_, _ string, _ time.Duration) { panic("not implemented") }
func (m *mockSecretController) UpdatedObjects(_ schema.GroupVersionKind, _, _ runtime.Object) ([]runtime.Object, error) {
	panic("not implemented")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// makeSecretController wires cache and API-fallback behaviour together.
// cacheErr: error returned by the cache lookup (nil = secret found).
// apiSecret/apiErr: response from the fallback live API call.
func makeSecretController(cacheErr error, apiSecret *corev1.Secret, apiErr error) *mockSecretController {
	var cacheSecret *corev1.Secret
	if cacheErr == nil {
		cacheSecret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name:      "my-secret",
			Namespace: RancherCredentialsNamespace,
		}}
	}
	return &mockSecretController{
		cacheObj:  &mockSecretCache{secret: cacheSecret, err: cacheErr},
		apiSecret: apiSecret,
		apiErr:    apiErr,
	}
}

func makeRequest(username string) *admission.Request {
	return &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UserInfo: authenticationv1.UserInfo{Username: username},
		},
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestIsMirroredCloudCredential(t *testing.T) {
	t.Parallel()

	mirroredSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "my-secret", Namespace: RancherCredentialsNamespace,
	}}
	notFoundErr := apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "my-secret")

	tests := []struct {
		name         string
		ctrl         *mockSecretController
		wantResult   bool
		wantErr      bool
		wantAPICalls int
	}{
		{
			name:         "cache hit — mirrored credential, no API call",
			ctrl:         makeSecretController(nil, nil, nil),
			wantResult:   true,
			wantAPICalls: 0,
		},
		// Cache NotFound is not definitive — always falls back to live API.
		{
			name:         "cache NotFound → API hit — mirrored credential",
			ctrl:         makeSecretController(notFoundErr, mirroredSecret, nil),
			wantResult:   true,
			wantAPICalls: 1,
		},
		{
			name:         "cache NotFound → API NotFound — user-managed",
			ctrl:         makeSecretController(notFoundErr, nil, notFoundErr),
			wantResult:   false,
			wantAPICalls: 1,
		},
		{
			name:         "cache NotFound → API error — fail closed",
			ctrl:         makeSecretController(notFoundErr, nil, fmt.Errorf("connection refused")),
			wantErr:      true,
			wantAPICalls: 1,
		},
		// Cache error also falls back to live API.
		{
			name:         "cache error → API hit — mirrored credential",
			ctrl:         makeSecretController(fmt.Errorf("informer not synced"), mirroredSecret, nil),
			wantResult:   true,
			wantAPICalls: 1,
		},
		{
			name:         "cache error → API NotFound — user-managed",
			ctrl:         makeSecretController(fmt.Errorf("informer not synced"), nil, notFoundErr),
			wantResult:   false,
			wantAPICalls: 1,
		},
		{
			name:         "cache error → API error — fail closed",
			ctrl:         makeSecretController(fmt.Errorf("informer not synced"), nil, fmt.Errorf("connection refused")),
			wantErr:      true,
			wantAPICalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsMirroredCloudCredential("my-secret", tt.ctrl)
			if (err != nil) != tt.wantErr {
				t.Fatalf("IsMirroredCloudCredential() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.wantResult {
				t.Errorf("IsMirroredCloudCredential() = %v, want %v", got, tt.wantResult)
			}
			if tt.ctrl.apiCalls != tt.wantAPICalls {
				t.Errorf("apiCalls = %d, want %d", tt.ctrl.apiCalls, tt.wantAPICalls)
			}
		})
	}
}

func TestCheckSecretAccess(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		sarAllowed  bool
		sarErr      error
		wantAllowed bool
		wantErr     bool
		wantCalls   int
	}{
		{name: "access granted", sarAllowed: true, wantAllowed: true, wantCalls: 1},
		{name: "access denied", sarAllowed: false, wantAllowed: false, wantCalls: 1},
		{name: "SAR call fails", sarErr: fmt.Errorf("connection refused"), wantErr: true, wantCalls: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sar := &mockSAR{allowed: tt.sarAllowed, err: tt.sarErr}
			resp, err := CheckSecretAccess(makeRequest("test-user"), "my-secret", sar)
			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckSecretAccess() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && resp.Allowed != tt.wantAllowed {
				t.Errorf("Allowed=%v, want %v", resp.Allowed, tt.wantAllowed)
			}
			if sar.calls != tt.wantCalls {
				t.Errorf("SAR calls=%d, want %d", sar.calls, tt.wantCalls)
			}
		})
	}
}
