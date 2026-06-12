package awscluster

import (
	"encoding/json"
	"fmt"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/infrastructure.cluster.x-k8s.io/v1beta2/capautils"
	corev1controller "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/trace"
	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
)

var (
	awsClusterGVR = schema.GroupVersionResource{
		Group:    "infrastructure.cluster.x-k8s.io",
		Version:  "v1beta2",
		Resource: "awsclusters",
	}

	awsStaticIdentityGVK = schema.GroupVersionKind{
		Group:   "infrastructure.cluster.x-k8s.io",
		Version: "v1beta2",
		Kind:    "AWSClusterStaticIdentity",
	}
)

// dynamicGetter is the subset of lasso's dynamic.Controller we need.
type dynamicGetter interface {
	Get(gvk schema.GroupVersionKind, namespace, name string) (runtime.Object, error)
}

// Validator implements admission.ValidatingAdmissionHandler for AWSCluster.
type Validator struct {
	dynamic dynamicGetter
	secrets corev1controller.SecretController
	sar     authorizationv1.SubjectAccessReviewInterface
}

// NewValidator creates a new AWSCluster validator.
func NewValidator(dynamic dynamicGetter, secrets corev1controller.SecretController, sar authorizationv1.SubjectAccessReviewInterface) *Validator {
	return &Validator{dynamic: dynamic, secrets: secrets, sar: sar}
}

// GVR returns the GroupVersionResource for this webhook.
func (v *Validator) GVR() schema.GroupVersionResource {
	return awsClusterGVR
}

// Operations returns the operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
		admissionregistrationv1.Update,
	}
}

// ValidatingWebhook returns the ValidatingWebhook configuration for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{
		*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope, v.Operations()),
	}
}

// Admitters returns the admitter for this validator.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{v}
}

// Admit handles the admission request for AWSCluster.
//
// When spec.identityRef references an AWSClusterStaticIdentity, the webhook
// fetches the current state of that identity (on both CREATE and UPDATE) and
// checks whether a Secret with the same name as spec.secretRef exists in
// cattle-global-data. If such a secret exists it is considered a Rancher Cloud
// Credential mirrored by Turtles, and the requesting user must have GET
// permission on it. If no such secret exists the identity is user-managed and
// the request is allowed.
//
// The identity is always fetched on UPDATE because the AWSClusterStaticIdentity
// itself may have changed between requests (different secretRef, mirror removed).
//
// Other identity kinds (AWSClusterRoleIdentity, AWSClusterControllerIdentity)
// are out of scope and are allowed through without a check.
func (v *Validator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("awsClusterValidator Admit",
		trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	newCluster, err := decodeCluster(request.Object.Raw)
	if err != nil {
		return admission.ResponseBadRequest(fmt.Sprintf("failed to decode AWSCluster: %v", err)), nil
	}

	// No identityRef — nothing to check.
	if newCluster.Spec.IdentityRef == nil {
		logrus.Debugf("awsClusterValidator: no identityRef on %s/%s, allowing", newCluster.Namespace, newCluster.Name)
		return admission.ResponseAllowed(), nil
	}

	// Only AWSClusterStaticIdentity is in scope.
	if newCluster.Spec.IdentityRef.Kind != infrav1.ClusterStaticIdentityKind {
		logrus.Debugf("awsClusterValidator: identityRef.kind=%s is not AWSClusterStaticIdentity for %s/%s, allowing",
			newCluster.Spec.IdentityRef.Kind, newCluster.Namespace, newCluster.Name)
		return admission.ResponseAllowed(), nil
	}

	identityName := newCluster.Spec.IdentityRef.Name

	// Fetch the current state of the AWSClusterStaticIdentity (cluster-scoped).
	// This is done on every admission — including UPDATE — because the identity
	// object itself may have changed between requests.
	identity, err := fetchStaticIdentity(v.dynamic, identityName)

	if apierrors.IsNotFound(err) {
		return admission.ResponseBadRequest(
			fmt.Sprintf("referenced AWSClusterStaticIdentity %q not found", identityName)), nil
	} else if err != nil {
		return admission.ResponseBadRequest(
			fmt.Sprintf("failed to look up referenced AWSClusterStaticIdentity %q: %v", identityName, err)), nil
	}

	secretName := identity.Spec.SecretRef
	if secretName == "" {
		logrus.Debugf("awsClusterValidator: AWSClusterStaticIdentity %s has no secretRef, allowing", identityName)
		return admission.ResponseAllowed(), nil
	}

	// Determine whether this is a Rancher-managed credential by checking for a
	// matching secret in cattle-global-data.
	mirrored, err := capautils.IsMirroredCloudCredential(secretName, v.secrets)
	if err != nil {
		return nil, fmt.Errorf("awsClusterValidator: %w", err)
	}
	if !mirrored {
		logrus.Debugf("awsClusterValidator: secret %s not found in %s, treating as user-managed, allowing",
			secretName, capautils.RancherCredentialsNamespace)
		return admission.ResponseAllowed(), nil
	}

	response, err := capautils.CheckSecretAccess(request, secretName, v.sar)
	if err == nil && !response.Allowed {
		logrus.Debugf("awsClusterValidator: access denied to secret %s/%s for user %q, denying",
			capautils.RancherCredentialsNamespace, secretName, request.UserInfo.Username)
	}
	return response, err
}

// fetchStaticIdentity retrieves an AWSClusterStaticIdentity via the dynamic controller.
// The identity is cluster-scoped so namespace is always empty.
func fetchStaticIdentity(d dynamicGetter, name string) (*infrav1.AWSClusterStaticIdentity, error) {
	obj, err := d.Get(awsStaticIdentityGVK, "", name)
	if err != nil {
		return nil, err
	}

	// Fast path: already typed (lasso cache seeded with scheme).
	if typed, ok := obj.(*infrav1.AWSClusterStaticIdentity); ok {
		return typed, nil
	}

	// Slow path: unstructured (lasso informer not seeded with CAPA scheme).
	unstr, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return nil, fmt.Errorf("unexpected type %T for AWSClusterStaticIdentity %q", obj, name)
	}
	out := &infrav1.AWSClusterStaticIdentity{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstr.Object, out); err != nil {
		return nil, fmt.Errorf("failed to convert AWSClusterStaticIdentity %q: %w", name, err)
	}
	return out, nil
}

// decodeCluster unmarshals raw JSON into an AWSCluster.
func decodeCluster(raw []byte) (*infrav1.AWSCluster, error) {
	obj := &infrav1.AWSCluster{}
	if err := json.Unmarshal(raw, obj); err != nil {
		return nil, err
	}
	return obj, nil
}
