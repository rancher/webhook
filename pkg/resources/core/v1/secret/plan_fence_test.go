package secret

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rancher/rancher/pkg/plan"
	planv1alpha1 "github.com/rancher/rancher/pkg/plan/api/plan.cattle.io/v1alpha1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/tools/cache"
)

const (
	operationKey = "operation.cattle.io/ETCDSnapshotSave/fleet-default/nightly/uid-1"
	otherKey     = "operation.cattle.io/CertificateRotation/fleet-default/rotate/uid-2"
)

type syncedInformer struct {
	cache.SharedIndexInformer
	synced atomic.Bool
}

func (s *syncedInformer) HasSynced() bool { return s.synced.Load() }

// fakeBeacons serves beacons as the dynamic controller does, unstructured, and counts the reads.
type fakeBeacons struct {
	beacons  map[string]*unstructured.Unstructured
	informer *syncedInformer
	getErr   error
	gets     int
}

func newFakeBeacons(t *testing.T, beacons ...*planv1alpha1.Beacon) *fakeBeacons {
	t.Helper()

	f := &fakeBeacons{beacons: map[string]*unstructured.Unstructured{}, informer: &syncedInformer{}}
	f.informer.synced.Store(true)
	for _, beacon := range beacons {
		object, err := runtime.DefaultUnstructuredConverter.ToUnstructured(beacon)
		require.NoError(t, err)
		u := &unstructured.Unstructured{Object: object}
		u.SetGroupVersionKind(beaconGVK)
		f.beacons[beacon.Namespace+"/"+beacon.Name] = u
	}
	return f
}

func (f *fakeBeacons) GetCache(_ context.Context, _ schema.GroupVersionKind) (cache.SharedIndexInformer, bool, error) {
	return f.informer, f.informer.HasSynced(), nil
}

func (f *fakeBeacons) Get(gvk schema.GroupVersionKind, namespace, name string) (runtime.Object, error) {
	f.gets++
	if f.getErr != nil {
		return nil, f.getErr
	}
	u, ok := f.beacons[namespace+"/"+name]
	if !ok {
		return nil, apierrors.NewNotFound(schema.GroupResource{Group: gvk.Group, Resource: "beacons"}, name)
	}
	return u, nil
}

func beacon(owner string, delegates ...string) *planv1alpha1.Beacon {
	return &planv1alpha1.Beacon{
		ObjectMeta: metav1.ObjectMeta{Namespace: "fleet-default", Name: "c"},
		Status:     planv1alpha1.BeaconStatus{Active: true, Owner: owner, Delegates: delegates},
	}
}

// planSecret is a machine-plan secret of the cluster whose beacon is fleet-default/c.
func planSecret() *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace:   "fleet-default",
			Name:        "machine-1-machine-plan",
			Labels:      map[string]string{planv1alpha1.ClusterLifecycleNameLabel: "c"},
			Annotations: map[string]string{},
		},
		Type: machinePlanSecretType,
		Data: map[string][]byte{},
	}
}

// assigned is planSecret with a plan assigned by writer.
func assigned(writer string) *corev1.Secret {
	secret := planSecret()
	secret.Data[plan.PlanDataKey] = []byte(`{}`)
	secret.Data[plan.PlanStateKey] = []byte(plan.PlanStatePending)
	if writer != "" {
		secret.Annotations[plan.PlanWriterAnnotation] = writer
	}
	return secret
}

func fenceRequest(t *testing.T, operation admissionv1.Operation, old, updated *corev1.Secret) *admission.Request {
	t.Helper()

	raw := func(secret *corev1.Secret) []byte {
		if secret == nil {
			return nil
		}
		data, err := json.Marshal(secret)
		require.NoError(t, err)
		return data
	}
	request := &admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: operation,
			Object:    runtime.RawExtension{Raw: raw(updated)},
			OldObject: runtime.RawExtension{Raw: raw(old)},
		},
	}
	if operation == admissionv1.Delete {
		request.Object = runtime.RawExtension{}
	}
	return request
}

// Only the writes that assign, retry, cancel or pause a plan, or name who did, are guarded. The agent's
// feedback and other controllers' bookkeeping keep being written after the writer has let the beacon
// go, so they are never checked.
func TestGuardedWrite(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		change func(*corev1.Secret)
		want   bool
	}{
		"nothing":                     {change: func(*corev1.Secret) {}},
		"the plan assigned":           {change: func(s *corev1.Secret) { s.Data[plan.PlanDataKey] = []byte(`{"instructions":[]}`) }, want: true},
		"the plan removed":            {change: func(s *corev1.Secret) { delete(s.Data, plan.PlanDataKey) }, want: true},
		"max-failures changed":        {change: func(s *corev1.Secret) { s.Data[maxFailuresKey] = []byte("2") }, want: true},
		"failure-threshold changed":   {change: func(s *corev1.Secret) { s.Data[failureThresholdKey] = []byte("2") }, want: true},
		"plan-state reset to pending": {change: func(s *corev1.Secret) { s.Data[plan.PlanStateKey] = []byte(plan.PlanStatePending) }, want: true},
		"plan-state progressing":      {change: func(s *corev1.Secret) { s.Data[plan.PlanStateKey] = []byte(plan.PlanStateSucceeded) }},
		"canceled":                    {change: func(s *corev1.Secret) { s.Annotations[plan.PlanCanceledAnnotation] = "true" }, want: true},
		"paused":                      {change: func(s *corev1.Secret) { s.Annotations[plan.PlanPausedAnnotation] = "true" }, want: true},
		"the writer changed":          {change: func(s *corev1.Secret) { s.Annotations[plan.PlanWriterAnnotation] = otherKey }, want: true},
		"the attempt changed":         {change: func(s *corev1.Secret) { s.Annotations[plan.PlanAttemptAnnotation] = "2" }, want: true},
		"the agent's revision":        {change: func(s *corev1.Secret) { s.Data[plan.PlanRevisionKey] = []byte("7") }},
		"the agent's checkpoint":      {change: func(s *corev1.Secret) { s.Data[plan.PlanCheckpointKey] = []byte(`{}`) }},
		"probe statuses":              {change: func(s *corev1.Secret) { s.Data["probe-statuses"] = []byte(`{}`) }},
		"applied-checksum":            {change: func(s *corev1.Secret) { s.Data["applied-checksum"] = []byte("abc") }},
		"the plansecret controller's": {change: func(s *corev1.Secret) { s.Data["appliedPlan"] = []byte(`{}`) }},
		"probes passed":               {change: func(s *corev1.Secret) { s.Annotations[plan.PlanProbesPassedAnnotation] = "now" }},
		"a label":                     {change: func(s *corev1.Secret) { s.Labels["rke.cattle.io/machine-id"] = "m" }},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			old := assigned(operationKey)
			old.Data[plan.PlanStateKey] = []byte(plan.PlanStateInProgress)
			updated := old.DeepCopy()
			tt.change(updated)

			assert.Equal(t, tt.want, guardedWrite(old, updated))
		})
	}

	t.Run("unpaused", func(t *testing.T) {
		t.Parallel()

		old := assigned(operationKey)
		old.Annotations[plan.PlanPausedAnnotation] = "true"
		updated := old.DeepCopy()
		delete(updated.Annotations, plan.PlanPausedAnnotation)
		assert.True(t, guardedWrite(old, updated))
	})

	t.Run("pending kept pending", func(t *testing.T) {
		t.Parallel()

		old := assigned(operationKey)
		updated := old.DeepCopy()
		updated.Data[plan.PlanRevisionKey] = []byte("1")
		assert.False(t, guardedWrite(old, updated), "only becoming pending is an assignment")
	})

	t.Run("a create with a plan", func(t *testing.T) {
		t.Parallel()

		assert.True(t, guardedWrite(&corev1.Secret{}, assigned(operationKey)))
		assert.False(t, guardedWrite(&corev1.Secret{}, planSecret()), "a machine-plan secret created empty assigns nothing")
	})
}

// The decision table: a guarded write must come from the beacon's owner or the delegate it last handed
// the beacon to. Writes with nothing to check against are allowed, and a beacon that can't be read
// fails the request for the writer to retry.
func TestPlanAdmitterAdmit_Fence(t *testing.T) {
	t.Parallel()

	reassign := func(writer string) (*corev1.Secret, *corev1.Secret) {
		old := assigned(operationKey)
		old.Data[plan.PlanStateKey] = []byte(plan.PlanStateSucceeded)
		updated := assigned(writer)
		updated.Data[plan.PlanDataKey] = []byte(`{"instructions":[{"name":"next"}]}`)
		return old, updated
	}
	cancel := func(writer string) (*corev1.Secret, *corev1.Secret) {
		old := assigned(operationKey)
		updated := old.DeepCopy()
		updated.Annotations[plan.PlanCanceledAnnotation] = "true"
		if writer == "" {
			delete(updated.Annotations, plan.PlanWriterAnnotation)
		} else {
			updated.Annotations[plan.PlanWriterAnnotation] = writer
		}
		return old, updated
	}

	tests := []struct {
		name      string
		operation admissionv1.Operation
		beacons   []*planv1alpha1.Beacon
		getErr    error
		write     func() (*corev1.Secret, *corev1.Secret)

		wantAllowed  bool
		wantErr      string
		wantMessage  string
		wantNoLookup bool
	}{
		{
			name: "the agent's feedback, after the beacon moved on", operation: admissionv1.Update,
			beacons: []*planv1alpha1.Beacon{beacon(otherKey)},
			write: func() (*corev1.Secret, *corev1.Secret) {
				old := assigned(operationKey)
				updated := old.DeepCopy()
				updated.Data[plan.PlanStateKey] = []byte(plan.PlanStateSucceeded)
				return old, updated
			},
			wantAllowed: true, wantNoLookup: true,
		},
		{
			name: "the owner assigning a plan", operation: admissionv1.Update,
			beacons:     []*planv1alpha1.Beacon{beacon(operationKey)},
			write:       func() (*corev1.Secret, *corev1.Secret) { return reassign(operationKey) },
			wantAllowed: true,
		},
		{
			name: "the owner canceling while it has delegated the beacon", operation: admissionv1.Update,
			beacons:     []*planv1alpha1.Beacon{beacon(operationKey, "hook-delegate")},
			write:       func() (*corev1.Secret, *corev1.Secret) { return cancel(operationKey) },
			wantAllowed: true,
		},
		{
			name: "the delegate it last handed the beacon to", operation: admissionv1.Update,
			beacons:     []*planv1alpha1.Beacon{beacon(otherKey, "first-delegate", "hook-delegate")},
			write:       func() (*corev1.Secret, *corev1.Secret) { return cancel("hook-delegate") },
			wantAllowed: true,
		},
		{
			name: "a delegate further down the chain", operation: admissionv1.Update,
			beacons:     []*planv1alpha1.Beacon{beacon(otherKey, "first-delegate", "hook-delegate")},
			write:       func() (*corev1.Secret, *corev1.Secret) { return cancel("first-delegate") },
			wantMessage: "written by first-delegate, but the beacon fleet-default/c is held by " + otherKey + ", delegated to hook-delegate",
		},
		{
			name: "a canceled operation's late write, once the next holds the beacon", operation: admissionv1.Update,
			beacons:     []*planv1alpha1.Beacon{beacon(otherKey)},
			write:       func() (*corev1.Secret, *corev1.Secret) { return reassign(operationKey) },
			wantMessage: "machine-plan fleet-default/machine-1-machine-plan written by " + operationKey + ", but the beacon fleet-default/c is held by " + otherKey,
		},
		{
			name: "a writer naming itself on a beacon it doesn't hold", operation: admissionv1.Update,
			beacons:     []*planv1alpha1.Beacon{beacon(operationKey)},
			write:       func() (*corev1.Secret, *corev1.Secret) { return reassign(otherKey) },
			wantMessage: "written by " + otherKey,
		},
		{
			name: "a beacon nobody holds", operation: admissionv1.Update,
			beacons:     []*planv1alpha1.Beacon{beacon("")},
			write:       func() (*corev1.Secret, *corev1.Secret) { return reassign(operationKey) },
			wantMessage: "the beacon fleet-default/c is not held by anyone",
		},
		{
			name: "a write without a writer, for one release", operation: admissionv1.Update,
			beacons:     []*planv1alpha1.Beacon{beacon(otherKey)},
			write:       func() (*corev1.Secret, *corev1.Secret) { return cancel("") },
			wantAllowed: true,
		},
		{
			name: "a secret without the cluster label", operation: admissionv1.Update,
			beacons: []*planv1alpha1.Beacon{beacon(otherKey)},
			write: func() (*corev1.Secret, *corev1.Secret) {
				old, updated := reassign(operationKey)
				delete(old.Labels, planv1alpha1.ClusterLifecycleNameLabel)
				delete(updated.Labels, planv1alpha1.ClusterLifecycleNameLabel)
				return old, updated
			},
			wantAllowed: true, wantNoLookup: true,
		},
		{
			// The beacon is found from the secret as it was, so the write that adds the label isn't
			// checked against the beacon it names.
			name: "the write adding the cluster label", operation: admissionv1.Update,
			beacons: []*planv1alpha1.Beacon{beacon(otherKey)},
			write: func() (*corev1.Secret, *corev1.Secret) {
				old, updated := reassign(operationKey)
				delete(old.Labels, planv1alpha1.ClusterLifecycleNameLabel)
				return old, updated
			},
			wantAllowed: true, wantNoLookup: true,
		},
		{
			name: "a beacon that doesn't exist", operation: admissionv1.Update,
			write:       func() (*corev1.Secret, *corev1.Secret) { return reassign(operationKey) },
			wantAllowed: true,
		},
		{
			name: "a beacon that can't be read", operation: admissionv1.Update,
			getErr:  errors.New("apiserver is down"),
			write:   func() (*corev1.Secret, *corev1.Secret) { return reassign(operationKey) },
			wantErr: "apiserver is down",
		},
		{
			name: "creating a secret with a plan, as the owner", operation: admissionv1.Create,
			beacons:     []*planv1alpha1.Beacon{beacon(operationKey)},
			write:       func() (*corev1.Secret, *corev1.Secret) { return nil, assigned(operationKey) },
			wantAllowed: true,
		},
		{
			name: "creating a secret with a plan, as someone else", operation: admissionv1.Create,
			beacons:     []*planv1alpha1.Beacon{beacon(otherKey)},
			write:       func() (*corev1.Secret, *corev1.Secret) { return nil, assigned(operationKey) },
			wantMessage: "written by " + operationKey,
		},
		{
			name: "deleting a secret", operation: admissionv1.Delete,
			beacons:     []*planv1alpha1.Beacon{beacon(otherKey)},
			write:       func() (*corev1.Secret, *corev1.Secret) { return assigned(operationKey), nil },
			wantAllowed: true, wantNoLookup: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			beacons := newFakeBeacons(t, tt.beacons...)
			beacons.getErr = tt.getErr
			old, updated := tt.write()

			response, err := (&planAdmitter{beacons: beacons}).Admit(fenceRequest(t, tt.operation, old, updated))
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, response.Allowed)
			if !tt.wantAllowed {
				require.NotNil(t, response.Result)
				assert.Equal(t, int32(http.StatusForbidden), response.Result.Code)
				assert.Contains(t, response.Result.Message, tt.wantMessage)
			}
			if tt.wantNoLookup {
				assert.Zero(t, beacons.gets, "nothing to check the write against, so the beacon isn't read")
			}
		})
	}
}

// An unsynced cache would read as a beacon that doesn't exist, which allows the write, so the fence
// waits for it to sync and fails the request, for the writer to retry, if it doesn't.
func TestPlanAdmitterAdmit_FenceWaitsForTheBeaconCache(t *testing.T) {
	previous := common.DynamicCacheSyncTimeout
	common.DynamicCacheSyncTimeout = 300 * time.Millisecond
	t.Cleanup(func() { common.DynamicCacheSyncTimeout = previous })

	beacons := newFakeBeacons(t, beacon(otherKey))
	beacons.informer.synced.Store(false)

	old := assigned(operationKey)
	updated := old.DeepCopy()
	updated.Data[plan.PlanDataKey] = []byte(`{"instructions":[]}`)
	_, err := (&planAdmitter{beacons: beacons}).Admit(fenceRequest(t, admissionv1.Update, old, updated))
	assert.ErrorContains(t, err, "timed out waiting for the Beacon cache to sync")
	assert.Zero(t, beacons.gets)
}
