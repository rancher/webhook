package secret

import (
	"bytes"
	"context"
	"fmt"
	"net/http"

	"github.com/rancher/rancher/pkg/plan"
	planv1alpha1 "github.com/rancher/rancher/pkg/plan/api/plan.cattle.io/v1alpha1"
	"github.com/rancher/webhook/pkg/resources/common"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var beaconGVK = planv1alpha1.SchemeGroupVersion.WithKind("Beacon")

// The data keys plan.Store writes along with a plan. They are unexported in pkg/plan.
const (
	maxFailuresKey      = "max-failures"
	failureThresholdKey = "failure-threshold"
)

// guardedData are the data keys only a plan's writer changes: the plan, and the failure limits it is
// assigned with.
var guardedData = []string{plan.PlanDataKey, maxFailuresKey, failureThresholdKey}

// guardedAnnotations are the annotations only a plan's writer changes: canceling or pausing the plan,
// and the writer key and attempt it was assigned under.
var guardedAnnotations = []string{
	plan.PlanCanceledAnnotation,
	plan.PlanPausedAnnotation,
	plan.PlanWriterAnnotation,
	plan.PlanAttemptAnnotation,
}

// beaconReader is the part of lasso's dynamic.Controller the fence reads beacons through.
type beaconReader interface {
	common.DynamicCacheGetter
	Get(gvk schema.GroupVersionKind, namespace, name string) (runtime.Object, error)
}

// guardedWrite reports whether a write of a machine-plan secret, from old to updated (old is empty on
// create), changes anything only the plan's writer may change. Everything else is the agent's feedback
// or another controller's bookkeeping (plan-state progress, revisions, checkpoints, probe statuses,
// outputs, the applied plan, labels), which keeps being written after the writer has let the beacon go
// and must pass whoever holds it.
//
// plan-state is guarded only when it becomes pending, which is how a plan is assigned or retried. The
// agent never persists pending: resuming a paused plan into pending is always folded into the same
// write that moves it on to in-progress.
func guardedWrite(old, updated *corev1.Secret) bool {
	for _, key := range guardedData {
		was, wasSet := old.Data[key]
		now, nowSet := updated.Data[key]
		if wasSet != nowSet || !bytes.Equal(was, now) {
			return true
		}
	}

	pending := string(plan.PlanStatePending)
	if string(updated.Data[plan.PlanStateKey]) == pending && string(old.Data[plan.PlanStateKey]) != pending {
		return true
	}

	for _, key := range guardedAnnotations {
		was, wasSet := old.Annotations[key]
		now, nowSet := updated.Annotations[key]
		if wasSet != nowSet || was != now {
			return true
		}
	}

	return false
}

// checkWriter fences a guarded write of a machine-plan secret to whoever holds the cluster's beacon:
// the writer the new secret names (plan.PlanWriterAnnotation) must be the beacon's owner, or the
// delegate the owner last handed it to (plan.AuthorizedForBeacon). It returns nil to allow the write.
//
// The beacon is found from the secret (plan.BeaconRefForSecret), using the old secret on update so a
// write can't choose the beacon it is checked against, and read from the webhook's cache. A write is
// allowed when there's nothing to check it against: a secret without the cluster lifecycle label, a
// beacon that doesn't exist (a cluster that predates beacons, or hasn't been given one yet), or, for
// one release so a newer webhook can run alongside a Rancher that doesn't name its writers yet, a write
// without a writer. A beacon that can't be read fails the request, for the writer to retry.
func (p *planAdmitter) checkWriter(ctx context.Context, old, updated *corev1.Secret, create bool) (*admissionv1.AdmissionResponse, error) {
	if !guardedWrite(old, updated) {
		return nil, nil
	}

	ref := old
	if create {
		ref = updated
	}
	namespace, name, ok := plan.BeaconRefForSecret(ref)
	if !ok {
		return nil, nil
	}

	beacon, err := p.beacon(ctx, namespace, name)
	if apierrors.IsNotFound(err) {
		return nil, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to read beacon %s/%s for machine-plan %s/%s: %w", namespace, name, updated.Namespace, updated.Name, err)
	}

	writer := updated.Annotations[plan.PlanWriterAnnotation]
	if writer == "" {
		// TODO: reject from the release after the one that introduces the writer annotation.
		logrus.Debugf("[%s] machine-plan %s/%s: guarded write without a %s annotation, allowing", logPrefix, updated.Namespace, updated.Name, plan.PlanWriterAnnotation)
		return nil, nil
	}

	if plan.AuthorizedForBeacon(beacon, writer) {
		return nil, nil
	}

	return &admissionv1.AdmissionResponse{
		Allowed: false,
		Result: &metav1.Status{
			Status:  metav1.StatusFailure,
			Message: fmt.Sprintf("machine-plan %s/%s written by %s, but the beacon %s/%s is %s", updated.Namespace, updated.Name, writer, namespace, name, beaconHolder(beacon)),
			Reason:  metav1.StatusReasonForbidden,
			Code:    http.StatusForbidden,
		},
	}, nil
}

// beacon reads a beacon from the dynamic controller's cache, waiting for it to sync first so an
// unsynced cache isn't taken for a beacon that doesn't exist.
func (p *planAdmitter) beacon(ctx context.Context, namespace, name string) (*planv1alpha1.Beacon, error) {
	if err := common.WaitForDynamicCache(ctx, p.beacons, beaconGVK); err != nil {
		return nil, err
	}

	obj, err := p.beacons.Get(beaconGVK, namespace, name)
	if err != nil {
		return nil, err
	}

	switch beacon := obj.(type) {
	case *planv1alpha1.Beacon:
		return beacon, nil
	case *unstructured.Unstructured:
		typed := &planv1alpha1.Beacon{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(beacon.Object, typed); err != nil {
			return nil, fmt.Errorf("failed to convert beacon %s/%s: %w", namespace, name, err)
		}
		return typed, nil
	}
	return nil, fmt.Errorf("unexpected type %T for beacon %s/%s", obj, namespace, name)
}

// beaconHolder describes who may write the beacon's plans, for a rejected write's message.
func beaconHolder(beacon *planv1alpha1.Beacon) string {
	owner := beacon.Status.Owner
	if owner == "" {
		return "not held by anyone"
	}
	if delegates := beacon.Status.Delegates; len(delegates) > 0 {
		return fmt.Sprintf("held by %s, delegated to %s", owner, delegates[len(delegates)-1])
	}
	return "held by " + owner
}
