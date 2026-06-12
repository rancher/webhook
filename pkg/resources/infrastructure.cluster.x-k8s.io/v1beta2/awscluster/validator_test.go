package awscluster

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/infrastructure.cluster.x-k8s.io/v1beta2/capautils"
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
	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
)

// ---------------------------------------------------------------------------
// mockSAR
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// mockDynamic
// ---------------------------------------------------------------------------

type mockDynamic struct {
	obj runtime.Object
	err error
}

func (m *mockDynamic) Get(_ schema.GroupVersionKind, _, _ string) (runtime.Object, error) {
	return m.obj, m.err
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
	cacheObj  *mockSecretCache
	apiSecret *corev1.Secret
	apiErr    error
	apiCalls  int
}

func (m *mockSecretController) Cache() generic.CacheInterface[*corev1.Secret] { return m.cacheObj }
func (m *mockSecretController) Get(_, _ string, _ metav1.GetOptions) (*corev1.Secret, error) {
	m.apiCalls++
	return m.apiSecret, m.apiErr
}

// ClientInterface stubs
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

// ControllerMeta stubs
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

// ControllerInterface stubs
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

func makeSecretController(cacheErr error, apiSecret *corev1.Secret, apiErr error) *mockSecretController {
	var cacheSecret *corev1.Secret
	if cacheErr == nil {
		cacheSecret = &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
			Name: "my-secret", Namespace: capautils.RancherCredentialsNamespace,
		}}
	}
	return &mockSecretController{
		cacheObj:  &mockSecretCache{secret: cacheSecret, err: cacheErr},
		apiSecret: apiSecret,
		apiErr:    apiErr,
	}
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
		Spec:       infrav1.AWSClusterStaticIdentitySpec{SecretRef: secretRef},
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestAWSClusterValidator_Admit(t *testing.T) {
	t.Parallel()

	notFound := apierrors.NewNotFound(schema.GroupResource{Resource: "secrets"}, "")
	mirroredSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{
		Name: "my-secret", Namespace: capautils.RancherCredentialsNamespace,
	}}

	tests := []struct {
		name         string
		operation    admissionv1.Operation
		newCluster   *infrav1.AWSCluster
		oldCluster   *infrav1.AWSCluster
		dynamicObj   runtime.Object
		dynamicErr   error
		secretCtrl   *mockSecretController
		sarAllowed   bool
		wantAllowed  bool
		wantErr      bool
		wantSARCalls int
		wantAPICalls int
	}{
		// --- No identityRef or non-static kind ---
		{
			name:         "CREATE no identityRef, allowed",
			operation:    admissionv1.Create,
			newCluster:   makeCluster("", ""),
			secretCtrl:   makeSecretController(nil, nil, nil),
			wantAllowed:  true,
			wantSARCalls: 0, wantAPICalls: 0,
		},
		{
			name:         "CREATE kind=AWSClusterRoleIdentity, allowed",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterRoleIdentityKind, "my-role-id"),
			secretCtrl:   makeSecretController(nil, nil, nil),
			wantAllowed:  true,
			wantSARCalls: 0, wantAPICalls: 0,
		},
		{
			name:         "CREATE kind=AWSClusterControllerIdentity, allowed",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ControllerIdentityKind, "default"),
			secretCtrl:   makeSecretController(nil, nil, nil),
			wantAllowed:  true,
			wantSARCalls: 0, wantAPICalls: 0,
		},

		// --- Dynamic lookup errors ---
		{
			name:         "CREATE identity not found → BadRequest",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "missing-id"),
			dynamicErr:   apierrors.NewNotFound(schema.GroupResource{Resource: "awsclusterstaticidentities"}, "missing-id"),
			secretCtrl:   makeSecretController(nil, nil, nil),
			wantAllowed:  false,
			wantSARCalls: 0, wantAPICalls: 0,
		},
		{
			name:         "CREATE identity lookup generic error → BadRequest",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicErr:   fmt.Errorf("no matches for kind"),
			secretCtrl:   makeSecretController(nil, nil, nil),
			wantAllowed:  false,
			wantSARCalls: 0, wantAPICalls: 0,
		},

		// --- Identity found, empty secretRef ---
		{
			name:         "CREATE empty secretRef, allowed without SAR",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity(""),
			secretCtrl:   makeSecretController(nil, nil, nil),
			wantAllowed:  true,
			wantSARCalls: 0, wantAPICalls: 0,
		},

		// --- Secret NOT in cattle-global-data: user-managed ---
		{
			name:         "CREATE no mirrored secret, user-managed, allowed",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCtrl:   makeSecretController(notFound, nil, notFound),
			wantAllowed:  true,
			wantSARCalls: 0, wantAPICalls: 1,
		},

		// --- Mirrored secret found: SAR enforced ---
		{
			name:         "CREATE mirrored secret, user has access",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCtrl:   makeSecretController(nil, nil, nil),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1, wantAPICalls: 0,
		},
		{
			name:         "CREATE mirrored secret, user lacks access",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCtrl:   makeSecretController(nil, nil, nil),
			sarAllowed:   false,
			wantAllowed:  false,
			wantSARCalls: 1, wantAPICalls: 0,
		},

		// --- Cache error → API fallback ---
		{
			name:         "CREATE cache error → API hit, user has access",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCtrl:   makeSecretController(fmt.Errorf("informer not synced"), mirroredSecret, nil),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1, wantAPICalls: 1,
		},
		{
			name:         "CREATE cache error → API hit, user lacks access",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCtrl:   makeSecretController(fmt.Errorf("informer not synced"), mirroredSecret, nil),
			sarAllowed:   false,
			wantAllowed:  false,
			wantSARCalls: 1, wantAPICalls: 1,
		},
		{
			name:         "CREATE cache error → API NotFound, user-managed, allowed",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCtrl:   makeSecretController(fmt.Errorf("informer not synced"), nil, notFound),
			wantAllowed:  true,
			wantSARCalls: 0, wantAPICalls: 1,
		},
		{
			name:         "CREATE cache error → API error, fail closed",
			operation:    admissionv1.Create,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-static-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCtrl:   makeSecretController(fmt.Errorf("informer not synced"), nil, fmt.Errorf("connection refused")),
			wantErr:      true,
			wantSARCalls: 0, wantAPICalls: 1,
		},

		// --- UPDATE: identity always re-fetched ---
		{
			name:         "UPDATE identityRef unchanged, identity re-fetched, mirrored, SAR enforced",
			operation:    admissionv1.Update,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "same-id"),
			oldCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "same-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCtrl:   makeSecretController(nil, nil, nil),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1, wantAPICalls: 0,
		},
		{
			name:         "UPDATE identityRef unchanged, no mirrored secret, allowed",
			operation:    admissionv1.Update,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "same-id"),
			oldCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "same-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCtrl:   makeSecretController(notFound, nil, notFound),
			wantAllowed:  true,
			wantSARCalls: 0, wantAPICalls: 1,
		},
		{
			name:         "UPDATE identityRef name changed, mirrored, user has access",
			operation:    admissionv1.Update,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "new-id"),
			oldCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "old-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCtrl:   makeSecretController(nil, nil, nil),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1, wantAPICalls: 0,
		},
		{
			name:         "UPDATE identityRef kind changed to static, mirrored, user lacks access",
			operation:    admissionv1.Update,
			newCluster:   makeCluster(infrav1.ClusterStaticIdentityKind, "my-id"),
			oldCluster:   makeCluster(infrav1.ClusterRoleIdentityKind, "my-id"),
			dynamicObj:   makeStaticIdentity("my-secret"),
			secretCtrl:   makeSecretController(nil, nil, nil),
			sarAllowed:   false,
			wantAllowed:  false,
			wantSARCalls: 1, wantAPICalls: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sar := &mockSAR{allowed: tt.sarAllowed}
			dyn := &mockDynamic{obj: tt.dynamicObj, err: tt.dynamicErr}
			v := NewValidator(dyn, tt.secretCtrl, sar)

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
			if tt.secretCtrl.apiCalls != tt.wantAPICalls {
				t.Errorf("apiCalls=%d, want %d", tt.secretCtrl.apiCalls, tt.wantAPICalls)
			}
		})
	}
}
