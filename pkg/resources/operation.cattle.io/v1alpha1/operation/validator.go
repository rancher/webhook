// Package operation validates the operation.cattle.io resources: ETCDSnapshotSave, ETCDSnapshotRestore,
// EncryptionKeyRotation and CertificateRotation. Every operation kind inlines the same OperationSpec and
// OperationStatus, so the rules are written once, against the kind-agnostic opv1alpha1.Operation, and
// registered for each resource.
package operation

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	opv1alpha1 "github.com/rancher/rancher/pkg/apis/operation.cattle.io/v1alpha1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/resources/common"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
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

// dynamicReader is the subset of lasso's dynamic.Controller used to read the operations on a cluster,
// and the cluster object an operation names.
type dynamicReader interface {
	GetCache(ctx context.Context, gvk schema.GroupVersionKind) (cache.SharedIndexInformer, bool, error)
	Get(gvk schema.GroupVersionKind, namespace, name string) (runtime.Object, error)
	List(gvk schema.GroupVersionKind, namespace string, selector labels.Selector) ([]runtime.Object, error)
}

// Validator validates one operation resource.
type Validator struct {
	gvr      schema.GroupVersionResource
	admitter admitter
}

type admitter struct {
	dynamic dynamicReader
	mapper  meta.RESTMapper
	sar     authorizationv1.SubjectAccessReviewInterface
}

// cluster is spec.clusterRef resolved: the kind and resource it names, and the namespace the object is
// read and reviewed in, which is empty for a cluster-scoped kind.
type cluster struct {
	ref       *corev1.ObjectReference
	gvk       schema.GroupVersionKind
	resource  schema.GroupVersionResource
	namespace string
}

// NewValidator returns a validator for the operation resource gvr, one of Kinds.
func NewValidator(gvr schema.GroupVersionResource, dynamic dynamicReader, mapper meta.RESTMapper, sar authorizationv1.SubjectAccessReviewInterface) *Validator {
	return &Validator{
		gvr: gvr,
		admitter: admitter{
			dynamic: dynamic,
			mapper:  mapper,
			sar:     sar,
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
//   - on create, no other operation may be in progress on the same cluster;
//   - on create, the cluster must exist, and its operation whitelist, if it has one, must list the
//     resource being created.
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

	target, response, err := a.resolveCluster(operation.Spec.ClusterRef)
	if response != nil || err != nil {
		return response, err
	}

	if response, err := a.checkClusterAccess(request, target); response != nil || err != nil {
		return response, err
	}

	// An operation in progress is reported before the whitelist it may have added: waiting for it, or
	// canceling it, is the first thing to do.
	if response, err := a.checkNoneInProgress(request, operation); response != nil || err != nil {
		return response, err
	}

	return a.checkWhitelist(request, target)
}

// admitUpdate checks the user's access to the cluster for an update that changes the spec. Updates
// that leave the spec alone (finalizers, lifecycle hook labels) don't act on the cluster, and an
// operation whose cluster can no longer be resolved must still be able to finish deleting.
func (a *admitter) admitUpdate(request *admission.Request, old, operation *opv1alpha1.Operation) (*admissionv1.AdmissionResponse, error) {
	if reflect.DeepEqual(old.Spec, operation.Spec) {
		return admission.ResponseAllowed(), nil
	}

	target, response, err := a.resolveCluster(operation.Spec.ClusterRef)
	if response != nil || err != nil {
		return response, err
	}

	if response, err := a.checkClusterAccess(request, target); response != nil || err != nil {
		return response, err
	}

	return admission.ResponseAllowed(), nil
}

// resolveCluster resolves clusterRef to the resource it names. A clusterRef that can't be resolved is
// rejected, since neither the user's access to the cluster nor its whitelist can be established, and
// so is one naming a namespaced resource without its namespace.
func (a *admitter) resolveCluster(clusterRef *corev1.ObjectReference) (*cluster, *admissionv1.AdmissionResponse, error) {
	if clusterRef == nil {
		return nil, admission.ResponseBadRequest("spec.clusterRef is required"), nil
	}

	gv, err := schema.ParseGroupVersion(clusterRef.APIVersion)
	if err != nil {
		return nil, admission.ResponseBadRequest(fmt.Sprintf("spec.clusterRef has an invalid apiVersion %q: %v", clusterRef.APIVersion, err)), nil
	}
	gvk := gv.WithKind(clusterRef.Kind)

	mapping, err := a.restMapping(gvk)
	if meta.IsNoMatchError(err) {
		return nil, admission.ResponseBadRequest(fmt.Sprintf("spec.clusterRef names %s %s, which is not a resource this cluster serves", clusterRef.APIVersion, clusterRef.Kind)), nil
	} else if err != nil {
		return nil, nil, fmt.Errorf("failed to resolve spec.clusterRef %s %s to a resource: %w", clusterRef.APIVersion, clusterRef.Kind, err)
	}

	namespace := ""
	if mapping.Scope.Name() == meta.RESTScopeNameNamespace {
		if clusterRef.Namespace == "" {
			return nil, admission.ResponseBadRequest(fmt.Sprintf("spec.clusterRef must name the namespace of %s %s, which is namespaced", clusterRef.Kind, clusterRef.Name)), nil
		}
		namespace = clusterRef.Namespace
	}

	return &cluster{ref: clusterRef, gvk: gvk, resource: mapping.Resource, namespace: namespace}, nil, nil
}

// checkClusterAccess requires the requesting user to have update on the cluster, checked with a
// SubjectAccessReview against the resource it resolves to. Operations mutate the cluster, so being
// able to read it isn't enough. It returns nil when the user has access.
func (a *admitter) checkClusterAccess(request *admission.Request, target *cluster) (*admissionv1.AdmissionResponse, error) {
	allowed, err := auth.RequestUserHasVerb(request, target.resource, a.sar, "update", target.ref.Name, target.namespace)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  metav1.StatusFailure,
				Message: fmt.Sprintf("user %q cannot update %s %s, which spec.clusterRef names; running an operation on a cluster requires it", request.UserInfo.Username, target.resource.GroupResource(), refName(target.namespace, target.ref.Name)),
				Reason:  metav1.StatusReasonForbidden,
				Code:    http.StatusForbidden,
			},
		}, nil
	}

	return nil, nil
}

// checkWhitelist rejects creating an operation the cluster's whitelist (opv1alpha1.WhitelistedAnnotation)
// doesn't list. An operation stopped after pausing the cluster whitelists etcd snapshot restores, since
// only a restore can repair the cluster from there. The cluster is read with the dynamic controller, so
// no typed cache is needed per cluster kind; a cluster that doesn't exist is rejected, since an operation
// on it could never run.
//
// The operation controllers check the whitelist again in their preflight, holding the cluster's beacon,
// so an operation this admits on a stale read is still turned away before it changes anything.
func (a *admitter) checkWhitelist(request *admission.Request, target *cluster) (*admissionv1.AdmissionResponse, error) {
	if err := a.waitForSync(request.Context, target.gvk); err != nil {
		return nil, err
	}

	obj, err := a.dynamic.Get(target.gvk, target.namespace, target.ref.Name)
	if apierrors.IsNotFound(err) {
		return admission.ResponseBadRequest(fmt.Sprintf("spec.clusterRef names %s %s, which does not exist", target.ref.Kind, refName(target.namespace, target.ref.Name))), nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to read %s %s, which spec.clusterRef names: %w", target.ref.Kind, refName(target.namespace, target.ref.Name), err)
	}

	object, err := meta.Accessor(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to read the metadata of %s %s: %w", target.ref.Kind, refName(target.namespace, target.ref.Name), err)
	}

	resource := request.Resource.Resource + "." + request.Resource.Group
	annotations := object.GetAnnotations()
	if opv1alpha1.Whitelisted(annotations, resource) {
		return admission.ResponseAllowed(), nil
	}

	return admission.ResponseBadRequest(fmt.Sprintf(
		"cluster %s only permits %s: an earlier operation was stopped after pausing it, and the cluster requires an etcd snapshot restore",
		refName(target.namespace, target.ref.Name), strings.Join(opv1alpha1.WhitelistEntries(annotations[opv1alpha1.WhitelistedAnnotation]), ", "))), nil
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
// Users cancel an operation in progress to clear the way for the next one. It returns nil when none is.
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

	return nil, nil
}

// list returns every operation of the given kind, in every namespace: an operation on a cluster-scoped
// cluster can be in any namespace. It waits for the kind's cache to sync first, and fails rather than
// read an unsynced cache, so the client retries.
func (a *admitter) list(ctx context.Context, gvk schema.GroupVersionKind) ([]runtime.Object, error) {
	if err := a.waitForSync(ctx, gvk); err != nil {
		return nil, err
	}

	objects, err := a.dynamic.List(gvk, "", labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to list %s: %w", gvk.Kind, err)
	}
	return objects, nil
}

// waitForSync waits for the dynamic controller's cache of gvk to sync: an unsynced cache would read as
// empty, with no operation in progress and no cluster. See common.WaitForDynamicCache.
func (a *admitter) waitForSync(ctx context.Context, gvk schema.GroupVersionKind) error {
	return common.WaitForDynamicCache(ctx, a.dynamic, gvk)
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
