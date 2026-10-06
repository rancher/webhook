package operation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	opv1alpha1 "github.com/rancher/rancher/pkg/apis/operation.cattle.io/v1alpha1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
)

var (
	capiCluster = schema.GroupVersionKind{Group: "cluster.x-k8s.io", Version: "v1beta2", Kind: "Cluster"}
	mgmtCluster = schema.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "Cluster"}
)

// fakeSAR answers every review with allowed, and records the reviews it was asked for.
type fakeSAR struct {
	allowed bool
	err     error
	reviews []*authorizationv1.SubjectAccessReview
}

func (f *fakeSAR) Create(_ context.Context, review *authorizationv1.SubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SubjectAccessReview, error) {
	f.reviews = append(f.reviews, review)
	if f.err != nil {
		return nil, f.err
	}
	return &authorizationv1.SubjectAccessReview{Status: authorizationv1.SubjectAccessReviewStatus{Allowed: f.allowed}}, nil
}

// fakeInformer reports synced once synced is set. Nothing else of the informer is used.
type fakeInformer struct {
	cache.SharedIndexInformer
	synced atomic.Bool
}

func (f *fakeInformer) HasSynced() bool { return f.synced.Load() }

// fakeOperations serves the operations of each kind, as the dynamic controller does: unstructured,
// with their kind set.
type fakeOperations struct {
	objects  map[schema.GroupVersionKind][]runtime.Object
	informer *fakeInformer
	listErr  error
}

func newFakeOperations(t *testing.T, operations ...runtime.Object) *fakeOperations {
	t.Helper()

	f := &fakeOperations{objects: map[schema.GroupVersionKind][]runtime.Object{}, informer: &fakeInformer{}}
	f.informer.synced.Store(true)
	for _, operation := range operations {
		object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(operation)
		require.NoError(t, err)
		u := &unstructured.Unstructured{Object: object}
		gvk := opv1alpha1.SchemeGroupVersion.WithKind(kindOf(operation))
		u.SetGroupVersionKind(gvk)
		f.objects[gvk] = append(f.objects[gvk], u)
	}
	return f
}

func (f *fakeOperations) GetCache(_ context.Context, _ schema.GroupVersionKind) (cache.SharedIndexInformer, bool, error) {
	return f.informer, f.informer.HasSynced(), nil
}

func (f *fakeOperations) List(gvk schema.GroupVersionKind, _ string, _ labels.Selector) ([]runtime.Object, error) {
	return f.objects[gvk], f.listErr
}

func kindOf(obj runtime.Object) string {
	switch obj.(type) {
	case *opv1alpha1.ETCDSnapshotSave:
		return "ETCDSnapshotSave"
	case *opv1alpha1.ETCDSnapshotRestore:
		return "ETCDSnapshotRestore"
	case *opv1alpha1.EncryptionKeyRotation:
		return "EncryptionKeyRotation"
	case *opv1alpha1.CertificateRotation:
		return "CertificateRotation"
	}
	panic("not an operation")
}

func newMapper() meta.RESTMapper {
	mapper := meta.NewDefaultRESTMapper(nil)
	mapper.Add(capiCluster, meta.RESTScopeNamespace)
	mapper.Add(mgmtCluster, meta.RESTScopeRoot)
	return mapper
}

func capiRef() *corev1.ObjectReference {
	return &corev1.ObjectReference{APIVersion: capiCluster.GroupVersion().String(), Kind: "Cluster", Namespace: "fleet-default", Name: "c"}
}

func mgmtRef() *corev1.ObjectReference {
	return &corev1.ObjectReference{APIVersion: mgmtCluster.GroupVersion().String(), Kind: "Cluster", Name: "c-abc"}
}

func save(name string, ref *corev1.ObjectReference) *opv1alpha1.ETCDSnapshotSave {
	return &opv1alpha1.ETCDSnapshotSave{
		ObjectMeta: metav1.ObjectMeta{Namespace: "fleet-default", Name: name},
		Spec:       opv1alpha1.ETCDSnapshotSaveSpec{OperationSpec: opv1alpha1.OperationSpec{ClusterRef: ref}},
	}
}

func rotation(name string, ref *corev1.ObjectReference) *opv1alpha1.CertificateRotation {
	return &opv1alpha1.CertificateRotation{
		ObjectMeta: metav1.ObjectMeta{Namespace: "fleet-default", Name: name},
		Spec:       opv1alpha1.CertificateRotationSpec{OperationSpec: opv1alpha1.OperationSpec{ClusterRef: ref}},
	}
}

func terminated(op *opv1alpha1.CertificateRotation) *opv1alpha1.CertificateRotation {
	op.Status.SetPhase(opv1alpha1.OperationPhaseCanceled)
	op.Status.SetTerminated()
	return op
}

func request(t *testing.T, operation admissionv1.Operation, obj, old runtime.Object) *admission.Request {
	t.Helper()

	raw := func(obj runtime.Object) []byte {
		if obj == nil {
			return nil
		}
		data, err := json.Marshal(obj)
		require.NoError(t, err)
		return data
	}

	return &admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: operation,
			Kind:      metav1.GroupVersionKind{Group: opv1alpha1.SchemeGroupVersion.Group, Version: "v1alpha1", Kind: kindOf(obj)},
			Object:    runtime.RawExtension{Raw: raw(obj)},
			OldObject: runtime.RawExtension{Raw: raw(old)},
			UserInfo:  authenticationv1.UserInfo{Username: "alice"},
		},
	}
}

func newAdmitter(operations *fakeOperations, sar *fakeSAR) *admitter {
	return &admitter{operations: operations, mapper: newMapper(), sar: sar}
}

func TestAdmit_Create(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		existing []runtime.Object
		obj      runtime.Object
		denied   bool

		wantAllowed bool
		wantCode    int32
		wantMessage string
		wantSAR     bool
	}{
		{
			name:        "an operation on an idle cluster",
			obj:         save("nightly", capiRef()),
			wantAllowed: true,
			wantSAR:     true,
		},
		{
			name: "spec.cancel set",
			obj: func() runtime.Object {
				op := save("nightly", capiRef())
				op.Spec.Cancel = true
				return op
			}(),
			wantCode:    http.StatusBadRequest,
			wantMessage: "spec.cancel cannot be set when creating an operation",
		},
		{
			name:        "no clusterRef",
			obj:         save("nightly", nil),
			wantCode:    http.StatusBadRequest,
			wantMessage: "spec.clusterRef is required",
		},
		{
			name:        "a clusterRef this cluster doesn't serve",
			obj:         save("nightly", &corev1.ObjectReference{APIVersion: "example.io/v1", Kind: "Cluster", Name: "c"}),
			wantCode:    http.StatusBadRequest,
			wantMessage: "not a resource this cluster serves",
		},
		{
			name: "a namespaced clusterRef without its namespace",
			obj: func() runtime.Object {
				ref := capiRef()
				ref.Namespace = ""
				return save("nightly", ref)
			}(),
			wantCode:    http.StatusBadRequest,
			wantMessage: "must name the namespace",
		},
		{
			name:        "a user who can't update the cluster",
			obj:         save("nightly", capiRef()),
			denied:      true,
			wantCode:    http.StatusForbidden,
			wantMessage: `user "alice" cannot update clusters.cluster.x-k8s.io fleet-default/c`,
			wantSAR:     true,
		},
		{
			name:        "another kind of operation in progress on the cluster",
			existing:    []runtime.Object{rotation("rotate", capiRef())},
			obj:         save("nightly", capiRef()),
			wantCode:    http.StatusBadRequest,
			wantMessage: "CertificateRotation fleet-default/rotate is still in progress on cluster fleet-default/c",
			wantSAR:     true,
		},
		{
			name: "an operation terminal but not yet terminated",
			existing: []runtime.Object{func() runtime.Object {
				op := rotation("rotate", capiRef())
				op.Status.SetPhase(opv1alpha1.OperationPhaseCanceled)
				return op
			}()},
			obj:         save("nightly", capiRef()),
			wantCode:    http.StatusBadRequest,
			wantMessage: "still in progress",
			wantSAR:     true,
		},
		{
			name:        "a terminated operation on the cluster",
			existing:    []runtime.Object{terminated(rotation("rotate", capiRef()))},
			obj:         save("nightly", capiRef()),
			wantAllowed: true,
			wantSAR:     true,
		},
		{
			name: "an operation in progress on another cluster",
			existing: []runtime.Object{rotation("rotate", func() *corev1.ObjectReference {
				ref := capiRef()
				ref.Name = "other"
				return ref
			}())},
			obj:         save("nightly", capiRef()),
			wantAllowed: true,
			wantSAR:     true,
		},
		{
			// A cluster-scoped cluster's operations can be in any namespace.
			name: "an operation in progress on a cluster-scoped cluster, from another namespace",
			existing: []runtime.Object{func() runtime.Object {
				op := rotation("rotate", mgmtRef())
				op.Namespace = "c-abc"
				return op
			}()},
			obj:         save("nightly", mgmtRef()),
			wantCode:    http.StatusBadRequest,
			wantMessage: "CertificateRotation c-abc/rotate is still in progress on cluster c-abc",
			wantSAR:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sar := &fakeSAR{allowed: !tt.denied}
			a := newAdmitter(newFakeOperations(t, tt.existing...), sar)

			response, err := a.Admit(request(t, admissionv1.Create, tt.obj, nil))
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, response.Allowed)
			if !tt.wantAllowed {
				require.NotNil(t, response.Result)
				assert.Equal(t, tt.wantCode, response.Result.Code)
				assert.Contains(t, response.Result.Message, tt.wantMessage)
			}

			if !tt.wantSAR {
				assert.Empty(t, sar.reviews)
				return
			}
			require.Len(t, sar.reviews, 1)
			attributes := sar.reviews[0].Spec.ResourceAttributes
			assert.Equal(t, "update", attributes.Verb)
			assert.Equal(t, "clusters", attributes.Resource)
			assert.Equal(t, "alice", sar.reviews[0].Spec.User)
		})
	}
}

// The access review targets the resource clusterRef resolves to, scoped as that resource is: a
// namespaced cluster's own namespace, and no namespace for a cluster-scoped one.
func TestAdmit_CreateReviewsTheResolvedResource(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		ref  *corev1.ObjectReference
		want authorizationv1.ResourceAttributes
	}{
		"a CAPI cluster": {
			ref:  capiRef(),
			want: authorizationv1.ResourceAttributes{Verb: "update", Group: "cluster.x-k8s.io", Version: "v1beta2", Resource: "clusters", Namespace: "fleet-default", Name: "c"},
		},
		"a management cluster": {
			ref:  &corev1.ObjectReference{APIVersion: mgmtCluster.GroupVersion().String(), Kind: "Cluster", Namespace: "ignored", Name: "c-abc"},
			want: authorizationv1.ResourceAttributes{Verb: "update", Group: "management.cattle.io", Version: "v3", Resource: "clusters", Name: "c-abc"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sar := &fakeSAR{allowed: true}
			response, err := newAdmitter(newFakeOperations(t), sar).Admit(request(t, admissionv1.Create, save("nightly", tc.ref), nil))
			require.NoError(t, err)
			assert.True(t, response.Allowed)
			require.Len(t, sar.reviews, 1)
			assert.Equal(t, tc.want, *sar.reviews[0].Spec.ResourceAttributes)
		})
	}
}

// Updates are checked for access only when they change the spec. Leaving the spec alone, as a
// finalizer or hook label update does, is always allowed, so an operation whose cluster can no longer
// be resolved can still finish deleting. An update is never turned away for another operation being in
// progress: that rule is about creating one.
func TestAdmit_Update(t *testing.T) {
	t.Parallel()

	inProgress := rotation("rotate", capiRef())

	for name, tc := range map[string]struct {
		old, obj    runtime.Object
		denied      bool
		wantAllowed bool
		wantSAR     bool
	}{
		"a label change": {
			old: save("nightly", capiRef()),
			obj: func() runtime.Object {
				op := save("nightly", capiRef())
				op.Labels = map[string]string{"hook": "delegate"}
				return op
			}(),
			wantAllowed: true,
		},
		"a label change on an unresolvable cluster": {
			old: save("nightly", &corev1.ObjectReference{APIVersion: "example.io/v1", Kind: "Cluster", Name: "c"}),
			obj: func() runtime.Object {
				op := save("nightly", &corev1.ObjectReference{APIVersion: "example.io/v1", Kind: "Cluster", Name: "c"})
				op.Finalizers = []string{}
				return op
			}(),
			wantAllowed: true,
		},
		"canceling with access": {
			old: save("nightly", capiRef()),
			obj: func() runtime.Object {
				op := save("nightly", capiRef())
				op.Spec.Cancel = true
				return op
			}(),
			wantAllowed: true,
			wantSAR:     true,
		},
		"canceling without access": {
			old: save("nightly", capiRef()),
			obj: func() runtime.Object {
				op := save("nightly", capiRef())
				op.Spec.Cancel = true
				return op
			}(),
			denied:  true,
			wantSAR: true,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			sar := &fakeSAR{allowed: !tc.denied}
			response, err := newAdmitter(newFakeOperations(t, inProgress), sar).Admit(request(t, admissionv1.Update, tc.obj, tc.old))
			require.NoError(t, err)
			assert.Equal(t, tc.wantAllowed, response.Allowed)
			if tc.wantSAR {
				assert.Len(t, sar.reviews, 1)
			} else {
				assert.Empty(t, sar.reviews)
			}
		})
	}
}

// An unsynced cache would read as no operation in progress, so a create waits for it to sync, and
// fails, for the client to retry, rather than read one that doesn't.
func TestAdmit_CreateWaitsForTheCacheToSync(t *testing.T) {
	previous := cacheSyncTimeout
	cacheSyncTimeout = 500 * time.Millisecond
	t.Cleanup(func() { cacheSyncTimeout = previous })

	t.Run("syncing in time", func(t *testing.T) {
		operations := newFakeOperations(t, rotation("rotate", capiRef()))
		operations.informer.synced.Store(false)
		go func() {
			time.Sleep(150 * time.Millisecond)
			operations.informer.synced.Store(true)
		}()

		response, err := newAdmitter(operations, &fakeSAR{allowed: true}).Admit(request(t, admissionv1.Create, save("nightly", capiRef()), nil))
		require.NoError(t, err)
		assert.False(t, response.Allowed, "the operation in progress is found once the cache has synced")
	})

	t.Run("never syncing", func(t *testing.T) {
		operations := newFakeOperations(t)
		operations.informer.synced.Store(false)

		_, err := newAdmitter(operations, &fakeSAR{allowed: true}).Admit(request(t, admissionv1.Create, save("nightly", capiRef()), nil))
		assert.ErrorContains(t, err, "timed out waiting for the ETCDSnapshotSave cache to sync")
	})
}

// Failures that may pass on retry are returned as errors, which the webhook reports as a server
// error, rather than as a rejection.
func TestAdmit_RetryableFailures(t *testing.T) {
	t.Parallel()

	t.Run("listing operations", func(t *testing.T) {
		t.Parallel()

		operations := newFakeOperations(t)
		operations.listErr = errors.New("boom")
		_, err := newAdmitter(operations, &fakeSAR{allowed: true}).Admit(request(t, admissionv1.Create, save("nightly", capiRef()), nil))
		assert.ErrorContains(t, err, "boom")
	})

	t.Run("the access review", func(t *testing.T) {
		t.Parallel()

		_, err := newAdmitter(newFakeOperations(t), &fakeSAR{err: errors.New("apiserver is down")}).Admit(request(t, admissionv1.Create, save("nightly", capiRef()), nil))
		assert.ErrorContains(t, err, "apiserver is down")
	})
}

// Each operation resource is served by its own webhook, for create and update only.
func TestValidators(t *testing.T) {
	t.Parallel()

	require.Len(t, Kinds, 4)
	for _, gvr := range Kinds {
		v := NewValidator(gvr, nil, nil, nil)
		assert.Equal(t, gvr, v.GVR())
		assert.ElementsMatch(t, []string{"CREATE", "UPDATE"}, func() []string {
			var ops []string
			for _, op := range v.Operations() {
				ops = append(ops, string(op))
			}
			return ops
		}())
		assert.Len(t, v.Admitters(), 1)
	}
}
