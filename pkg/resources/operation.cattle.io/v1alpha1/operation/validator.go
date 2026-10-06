// Package operation validates the operation.cattle.io resources: ETCDSnapshotSave, ETCDSnapshotRestore,
// EncryptionKeyRotation and CertificateRotation. Every operation kind inlines the same OperationSpec and
// OperationStatus, so the rules are written once, against the kind-agnostic opv1alpha1.Operation, and
// registered for each resource.
package operation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"time"

	opv1alpha1 "github.com/rancher/rancher/pkg/apis/operation.cattle.io/v1alpha1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/utils/trace"
)

// Kinds are the operation kinds this package validates, each served by its own webhook.
var Kinds = []schema.GroupVersionResource{
	opv1alpha1.SchemeGroupVersion.WithResource("etcdsnapshotsaves"),
	opv1alpha1.SchemeGroupVersion.WithResource("etcdsnapshotrestores"),
	opv1alpha1.SchemeGroupVersion.WithResource("encryptionkeyrotations"),
	opv1alpha1.SchemeGroupVersion.WithResource("certificaterotations"),
}

// operationGVKs are the kinds listed to find the operations already running on a cluster. Every kind
// counts, whatever kind is being created: only one operation may run on a cluster at a time.
var operationGVKs = []schema.GroupVersionKind{
	opv1alpha1.SchemeGroupVersion.WithKind("ETCDSnapshotSave"),
	opv1alpha1.SchemeGroupVersion.WithKind("ETCDSnapshotRestore"),
	opv1alpha1.SchemeGroupVersion.WithKind("EncryptionKeyRotation"),
	opv1alpha1.SchemeGroupVersion.WithKind("CertificateRotation"),
}

// cacheSyncTimeout bounds how long a create waits for the operation caches to sync. The dynamic
// controller registers an informer the first time a kind is asked for, so the first creates after the
// webhook starts may find one still syncing; an empty unsynced cache would read as no operation in
// progress.
var cacheSyncTimeout = 10 * time.Second

// operationLister is the subset of lasso's dynamic.Controller used to find the operations on a cluster.
type operationLister interface {
	GetCache(ctx context.Context, gvk schema.GroupVersionKind) (cache.SharedIndexInformer, bool, error)
	List(gvk schema.GroupVersionKind, namespace string, selector labels.Selector) ([]runtime.Object, error)
}

// Validator validates one operation resource.
type Validator struct {
	gvr      schema.GroupVersionResource
	admitter admitter
}

type admitter struct {
	operations operationLister
	mapper     meta.RESTMapper
	sar        authorizationv1.SubjectAccessReviewInterface
}

// NewValidator returns a validator for the operation resource gvr, one of Kinds.
func NewValidator(gvr schema.GroupVersionResource, operations operationLister, mapper meta.RESTMapper, sar authorizationv1.SubjectAccessReviewInterface) *Validator {
	return &Validator{
		gvr: gvr,
		admitter: admitter{
			operations: operations,
			mapper:     mapper,
			sar:        sar,
		},
	}
}

// GVR returns the GroupVersionResource this validator handles.
func (v *Validator) GVR() schema.GroupVersionResource {
	return v.gvr
}

// Operations returns the admission operations this validator handles. Deletes are not validated.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update}
}

// ValidatingWebhook returns the ValidatingWebhook configuration for this resource.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{
		*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope, v.Operations()),
	}
}

// Admitters returns the admitters for this validator.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

// Admit validates an operation being created or updated:
//
//   - on create, spec.cancel can't be set;
//   - on create, and on an update that changes the spec, the requesting user must be able to update
//     the cluster spec.clusterRef names;
//   - on create, no other operation may be in progress on the same cluster.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("operationValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	operation, err := decode(request.Object.Raw)
	if err != nil {
		return admission.ResponseBadRequest(fmt.Sprintf("failed to decode %s: %v", request.Kind.Kind, err)), nil
	}
	operation.Kind = request.Kind.Kind

	switch request.Operation {
	case admissionv1.Create:
		return a.admitCreate(request, operation)
	case admissionv1.Update:
		old, err := decode(request.OldObject.Raw)
		if err != nil {
			return admission.ResponseBadRequest(fmt.Sprintf("failed to decode old %s: %v", request.Kind.Kind, err)), nil
		}
		return a.admitUpdate(request, old, operation)
	}

	return admission.ResponseAllowed(), nil
}

func (a *admitter) admitCreate(request *admission.Request, operation *opv1alpha1.Operation) (*admissionv1.AdmissionResponse, error) {
	// spec.cancel latches, and the CRD's CEL rules hold it there once set, but CEL can't tell a create
	// from an update, so creating an operation already canceled is turned away here.
	if operation.Spec.Cancel {
		return admission.ResponseBadRequest("spec.cancel cannot be set when creating an operation"), nil
	}

	if response, err := a.checkClusterAccess(request, operation.Spec.ClusterRef); response != nil || err != nil {
		return response, err
	}

	return a.checkNoneInProgress(request, operation)
}

// admitUpdate checks the user's access to the cluster for an update that changes the spec. Updates
// that leave the spec alone (finalizers, lifecycle hook labels) don't act on the cluster, and an
// operation whose cluster can no longer be resolved must still be able to finish deleting.
func (a *admitter) admitUpdate(request *admission.Request, old, operation *opv1alpha1.Operation) (*admissionv1.AdmissionResponse, error) {
	if reflect.DeepEqual(old.Spec, operation.Spec) {
		return admission.ResponseAllowed(), nil
	}

	if response, err := a.checkClusterAccess(request, operation.Spec.ClusterRef); response != nil || err != nil {
		return response, err
	}

	return admission.ResponseAllowed(), nil
}

// checkClusterAccess requires the requesting user to have update on the cluster clusterRef names,
// checked with a SubjectAccessReview against the resource it resolves to. Operations mutate the
// cluster, so being able to read it isn't enough. A clusterRef that can't be resolved to a resource is
// rejected, since the permission can't be established. It returns nil when the user has access.
func (a *admitter) checkClusterAccess(request *admission.Request, clusterRef *corev1.ObjectReference) (*admissionv1.AdmissionResponse, error) {
	if clusterRef == nil {
		return admission.ResponseBadRequest("spec.clusterRef is required"), nil
	}

	gv, err := schema.ParseGroupVersion(clusterRef.APIVersion)
	if err != nil {
		return admission.ResponseBadRequest(fmt.Sprintf("spec.clusterRef has an invalid apiVersion %q: %v", clusterRef.APIVersion, err)), nil
	}

	mapping, err := a.restMapping(gv.WithKind(clusterRef.Kind))
	if meta.IsNoMatchError(err) {
		return admission.ResponseBadRequest(fmt.Sprintf("spec.clusterRef names %s %s, which is not a resource this cluster serves", clusterRef.APIVersion, clusterRef.Kind)), nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to resolve spec.clusterRef %s %s to a resource: %w", clusterRef.APIVersion, clusterRef.Kind, err)
	}

	namespace := ""
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		if clusterRef.Namespace == "" {
			return admission.ResponseBadRequest(fmt.Sprintf("spec.clusterRef must name the namespace of %s %s, which is namespaced", clusterRef.Kind, clusterRef.Name)), nil
		}
		namespace = clusterRef.Namespace
	}

	allowed, err := auth.RequestUserHasVerb(request, mapping.Resource, a.sar, "update", clusterRef.Name, namespace)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: fmt.Sprintf("user %q cannot update %s %s, which spec.clusterRef names; running an operation on a cluster requires it", request.UserInfo.Username, mapping.Resource.GroupResource(), refName(namespace, clusterRef.Name)),
				Reason:  metav1.StatusReasonForbidden,
				Code:    http.StatusForbidden,
			},
		}, nil
	}

	return nil, nil
}

// restMapping resolves gvk to a resource. The mapper caches discovery, so a kind it doesn't know is
// looked up once more after resetting it, for a cluster type installed since the mapper last refreshed.
func (a *admitter) restMapping(gvk schema.GroupVersionKind) (*meta.RESTMapping, error) {
	mapping, err := a.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if meta.IsNoMatchError(err) {
		if resettable, ok := a.mapper.(meta.ResettableRESTMapper); ok {
			resettable.Reset()
			mapping, err = a.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		}
	}
	return mapping, err
}

// checkNoneInProgress rejects creating an operation while another operation on the same cluster, of
// any kind, is in progress: it has not terminated (status.terminatedAt is unset), whatever its phase.
// Users cancel an operation in progress to clear the way for the next one.
//
// The operations are read from a cache, so two creates in quick succession can both be admitted; the
// operation controllers reject whichever one fails to acquire the cluster's beacon first.
func (a *admitter) checkNoneInProgress(request *admission.Request, operation *opv1alpha1.Operation) (*admissionv1.AdmissionResponse, error) {
	for _, gvk := range operationGVKs {
		objects, err := a.list(request.Context, gvk)
		if err != nil {
			return nil, err
		}

		for _, obj := range objects {
			other, err := opv1alpha1.ToOperation(obj)
			if err != nil {
				return nil, err
			}
			other.Kind = gvk.Kind

			if other.SameAs(operation) || other.Status.IsTerminated() || !opv1alpha1.SameCluster(other.Spec.ClusterRef, operation.Spec.ClusterRef) {
				continue
			}

			return admission.ResponseBadRequest(fmt.Sprintf(
				"%s %s is still in progress on cluster %s; only one operation may run on a cluster at a time, so wait for it to finish (status.terminatedAt is set) or cancel it (spec.cancel: true), then create this operation again",
				other.Kind, refName(other.Metadata.Namespace, other.Metadata.Name), clusterName(operation.Spec.ClusterRef))), nil
		}
	}

	return admission.ResponseAllowed(), nil
}

// list returns every operation of the given kind, in every namespace: an operation on a cluster-scoped
// cluster can be in any namespace. It waits for the kind's cache to sync first, and fails rather than
// read an unsynced cache, so the client retries.
func (a *admitter) list(ctx context.Context, gvk schema.GroupVersionKind) ([]runtime.Object, error) {
	informer, synced, err := a.operations.GetCache(ctx, gvk)
	if err != nil {
		return nil, fmt.Errorf("failed to get the %s cache: %w", gvk.Kind, err)
	}
	if !synced {
		waitCtx, cancel := context.WithTimeout(ctx, cacheSyncTimeout)
		defer cancel()
		if !cache.WaitForCacheSync(waitCtx.Done(), informer.HasSynced) {
			return nil, errors.New("timed out waiting for the " + gvk.Kind + " cache to sync, retry the request")
		}
	}

	objects, err := a.operations.List(gvk, "", labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to list %s: %w", gvk.Kind, err)
	}
	return objects, nil
}

func decode(raw []byte) (*opv1alpha1.Operation, error) {
	operation := &opv1alpha1.Operation{}
	if err := json.Unmarshal(raw, operation); err != nil {
		return nil, err
	}
	return operation, nil
}

func refName(namespace, name string) string {
	if namespace == "" {
		return name
	}
	return namespace + "/" + name
}

func clusterName(ref *corev1.ObjectReference) string {
	if ref == nil {
		return ""
	}
	return refName(ref.Namespace, ref.Name)
}
