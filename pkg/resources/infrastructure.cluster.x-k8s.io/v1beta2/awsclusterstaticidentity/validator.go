package awsclusterstaticidentity

import (
	"encoding/json"
	"fmt"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/infrastructure.cluster.x-k8s.io/v1beta2/capautils"
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
	sar authorizationv1.SubjectAccessReviewInterface
}

// NewValidator creates a new AWSClusterStaticIdentity validator.
func NewValidator(sar authorizationv1.SubjectAccessReviewInterface) *Validator {
	return &Validator{sar: sar}
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
// The credential access check is only enforced when the identity carries the
// annotation "cluster-api.cattle.io/source-id", indicating it is managed by
// Rancher Turtles. Without that annotation the request is allowed immediately.
//
// When enforced, the webhook verifies that the requesting user has GET
// permission on the Rancher Cloud Credential Secret (in cattle-global-data)
// referenced by spec.secretRef. If secretRef is empty, or is unchanged on
// UPDATE, the request is allowed without performing a SubjectAccessReview.
func (v *Validator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("awsClusterStaticIdentityValidator Admit",
		trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	newIdentity, err := decodeIdentity(request.Object.Raw)
	if err != nil {
		return admission.ResponseBadRequest(fmt.Sprintf("failed to decode AWSClusterStaticIdentity: %v", err)), nil
	}

	// Only enforce for Rancher-managed identities.
	if !capautils.HasSourceIDAnnotation(newIdentity) {
		logrus.Debugf("awsClusterStaticIdentityValidator: no %s annotation on %s, allowing",
			capautils.AnnotationSourceID, newIdentity.Name)
		return admission.ResponseAllowed(), nil
	}

	secretName := newIdentity.Spec.SecretRef
	if secretName == "" {
		logrus.Debugf("awsClusterStaticIdentityValidator: no secretRef on %s, allowing", newIdentity.Name)
		return admission.ResponseAllowed(), nil
	}

	// On UPDATE, skip SAR if secretRef has not changed.
	if request.Operation == admissionv1.Update {
		oldIdentity, err := decodeIdentity(request.OldObject.Raw)
		if err != nil {
			return admission.ResponseBadRequest(fmt.Sprintf("failed to decode old AWSClusterStaticIdentity: %v", err)), nil
		}
		if oldIdentity.Spec.SecretRef == secretName {
			logrus.Debugf("awsClusterStaticIdentityValidator: secretRef unchanged for %s, allowing", newIdentity.Name)
			return admission.ResponseAllowed(), nil
		}
	}

	return capautils.CheckSecretAccess(request, secretName, v.sar)
}

// decodeIdentity unmarshals raw JSON into an AWSClusterStaticIdentity.
func decodeIdentity(raw []byte) (*infrav1.AWSClusterStaticIdentity, error) {
	obj := &infrav1.AWSClusterStaticIdentity{}
	if err := json.Unmarshal(raw, obj); err != nil {
		return nil, err
	}
	return obj, nil
}
