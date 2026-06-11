package awsclusterstaticidentity

import (
	"encoding/json"
	"fmt"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/infrastructure.cluster.x-k8s.io/v1beta2/capautils"
	corev1controller "github.com/rancher/wrangler/v3/pkg/generated/controllers/core/v1"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/trace"
	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
)

var awsStaticIdentityGVR = schema.GroupVersionResource{
	Group:    "infrastructure.cluster.x-k8s.io",
	Version:  "v1beta2",
	Resource: "awsclusterstaticidentities",
}

// Validator implements admission.ValidatingAdmissionHandler for AWSClusterStaticIdentity.
type Validator struct {
	secretCache corev1controller.SecretCache
	sar         authorizationv1.SubjectAccessReviewInterface
}

// NewValidator creates a new AWSClusterStaticIdentity validator.
func NewValidator(secretCache corev1controller.SecretCache, sar authorizationv1.SubjectAccessReviewInterface) *Validator {
	return &Validator{secretCache: secretCache, sar: sar}
}

// GVR returns the GroupVersionResource for this webhook.
func (v *Validator) GVR() schema.GroupVersionResource {
	return awsStaticIdentityGVR
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
		*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope, v.Operations()),
	}
}

// Admitters returns the admitter for this validator.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{v}
}

// Admit handles the admission request for AWSClusterStaticIdentity.
//
// The credential access check is only enforced when a Secret with the same
// name as spec.secretRef exists in cattle-global-data, indicating it is a
// Rancher Cloud Credential mirrored by Turtles into the CAPA provider
// namespace. If no such secret exists the identity is considered user-managed
// and the request is allowed without further checks.
//
// When enforced, the webhook verifies that the requesting user has GET
// permission on that secret. If secretRef is empty, the request is allowed
// without performing a SubjectAccessReview.
func (v *Validator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("awsClusterStaticIdentityValidator Admit",
		trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	newIdentity, err := decodeIdentity(request.Object.Raw)
	if err != nil {
		return admission.ResponseBadRequest(fmt.Sprintf("failed to decode AWSClusterStaticIdentity: %v", err)), nil
	}

	secretName := newIdentity.Spec.SecretRef
	if secretName == "" {
		logrus.Debugf("awsClusterStaticIdentityValidator: no secretRef on %s, allowing", newIdentity.Name)
		return admission.ResponseAllowed(), nil
	}

	// Determine whether this is a Rancher-managed credential by checking for a
	// matching secret in cattle-global-data.
	mirrored, err := capautils.IsMirroredCloudCredential(secretName, v.secretCache)
	if err != nil {
		return nil, fmt.Errorf("awsClusterStaticIdentityValidator: %w", err)
	}
	if !mirrored {
		logrus.Debugf("awsClusterStaticIdentityValidator: secret %s not found in %s, treating as user-managed, allowing",
			secretName, capautils.RancherCredentialsNamespace)
		return admission.ResponseAllowed(), nil
	}

	response, err := capautils.CheckSecretAccess(request, secretName, v.sar)
	if err == nil && !response.Allowed {
		logrus.Debugf("awsClusterStaticIdentityValidator: access denied to secret %s/%s for user %q, denying",
			capautils.RancherCredentialsNamespace, secretName, request.UserInfo.Username)
	}
	return response, err
}

// decodeIdentity unmarshals raw JSON into an AWSClusterStaticIdentity.
func decodeIdentity(raw []byte) (*infrav1.AWSClusterStaticIdentity, error) {
	obj := &infrav1.AWSClusterStaticIdentity{}
	if err := json.Unmarshal(raw, obj); err != nil {
		return nil, err
	}
	return obj, nil
}
