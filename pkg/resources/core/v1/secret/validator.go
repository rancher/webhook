package secret

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/rancher/webhook/pkg/admission"
	ctrlv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	provcontrollers "github.com/rancher/webhook/pkg/generated/controllers/provisioning.cattle.io/v1"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	v1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/rbac/v1"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

const (
	roleOwnerIndex        = "webhook.cattle.io/role-owner-index"
	roleBindingOwnerIndex = "webhook.cattle.io/role-binding-owner-index"
	logPrefix             = "validator/corev1/secret"
)

// Validator implements admission.ValidatingAdmissionWebhook.
type Validator struct {
	admitter admitter
}

// NewValidator creates a new secret validator that handles both cloud credential validation and
// RBAC orphan protection. Cloud credential secrets (in cattle-cloud-credentials with the
// rke.cattle.io/cloud-credential- type prefix) are validated against their DynamicSchema and
// checked for in-use references on delete. All other secrets are checked for RBAC orphan
// protection on delete.
func NewValidator(roleCache v1.RoleCache, roleBindingCache v1.RoleBindingCache,
	dynamicSchemaCache ctrlv3.DynamicSchemaCache, featureCache ctrlv3.FeatureCache, provClusterCache provcontrollers.ClusterCache) *Validator {
	roleCache.AddIndexer(roleOwnerIndex, func(obj *rbacv1.Role) ([]string, error) {
		return secretOwnerIndexer(obj.ObjectMeta), nil
	})
	roleBindingCache.AddIndexer(roleBindingOwnerIndex, func(obj *rbacv1.RoleBinding) ([]string, error) {
		return secretOwnerIndexer(obj.ObjectMeta), nil
	})

	provClusterCache.AddIndexer(byCloudCred, byCloudCredentialIndex)
	provClusterCache.AddIndexer(byMachinePoolCloudCred, byMachinePoolCloudCredIndex)
	provClusterCache.AddIndexer(byEtcdS3CloudCred, byEtcdS3CloudCredIndex)

	return &Validator{
		admitter: admitter{
			roleCache:        roleCache,
			roleBindingCache: roleBindingCache,
			cloudAdmitter: cloudCredentialAdmitter{
				dynamicSchemaCache: dynamicSchemaCache,
				featureCache:       featureCache,
				provClusterCache:   provClusterCache,
			},
		},
	}
}

// secretOwnerIndexer indexes an object based on all owning secrets.
func secretOwnerIndexer(objMeta metav1.ObjectMeta) []string {
	var owningSecrets []string
	for _, owner := range objMeta.OwnerReferences {
		if owner.APIVersion == gvr.Version && owner.Kind == secretKind {
			owningSecrets = append(owningSecrets, fmt.Sprintf(ownerFormat, objMeta.Namespace, owner.Name))
		}
	}
	return owningSecrets
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
		admissionregistrationv1.Update,
		admissionregistrationv1.Delete,
	}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	validatingWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope, v.Operations())
	validatingWebhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNone)
	validatingWebhook.MatchConditions = []admissionregistrationv1.MatchCondition{
		{
			Name: "delete-or-cloud-credential-only",
			// always let DELETE requests through, or if the secret type is a cloud-credential
			Expression: "request.operation == 'DELETE' || (object.type.startsWith('rke.cattle.io/cloud-credential-') && object.metadata.namespace == 'cattle-cloud-credentials')",
		},
	}
	return []admissionregistrationv1.ValidatingWebhook{*validatingWebhook}
}

// Admitters returns the admitter objects used to validate secrets.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
	roleCache        v1.RoleCache
	roleBindingCache v1.RoleBindingCache
	cloudAdmitter    cloudCredentialAdmitter
}

// Admit is the entrypoint for the validator. Admit will return an error if it is unable to process the request.
// Cloud credential secrets are dispatched to the cloud credential admitter. All other secrets
// are checked for RBAC orphan protection on delete.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("secret Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	secret, err := objectsv1.SecretFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to read secret from request: %w", err)
	}

	// Cloud credential secrets have their own validation logic.
	if isCloudCredentialSecret(secret) {
		return a.cloudAdmitter.AdmitCloudCredential(secret, request)
	}

	// For non-cloud-credential secrets, only Delete operations need validation.
	if request.Operation != admissionv1.Delete {
		return admission.ResponseAllowed(), nil
	}

	return a.AdmitOrphaned(secret, request)
}

func (a *admitter) AdmitOrphaned(secret *corev1.Secret, request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	var deleteOpts metav1.DeleteOptions
	err := json.Unmarshal(request.Options.Raw, &deleteOpts)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal delete options %w", err)
	}
	hasOrphanPolicy := deleteOpts.PropagationPolicy != nil && *deleteOpts.PropagationPolicy == metav1.DeletePropagationOrphan
	// we are only concerned with requests that attempt to orphan resources
	if !hasOrphanPolicy {
		return admission.ResponseAllowed(), nil
	}
	roles, roleBindings, err := a.getRbacRefs(secret)
	if err != nil {
		return nil, fmt.Errorf("unable to determine if secret has rbac refs: %w", err)
	}
	if logrus.IsLevelEnabled(logrus.DebugLevel) {
		roleNames := make([]string, len(roles))
		roleBindingNames := make([]string, len(roleBindings))
		for i := range roles {
			roleNames[i] = roles[i].Name
		}
		for i := range roleBindings {
			roleBindingNames[i] = roleBindings[i].Name
		}
		logrus.Debugf("[%s] secret %s owns roles: %v and roleBindings %v", logPrefix, secret.Name, roleNames, roleBindingNames)
	}
	// requests which orphan non-rbac resources are allowed
	if len(roles) == 0 && len(roleBindings) == 0 {
		return admission.ResponseAllowed(), nil
	}
	// secret orphans rbac resources, deny the request
	return admission.ResponseBadRequest("A secret which owns RBAC objects cannot be deleted with OrphanDependents: true or PropagationPolicy: Orphan"), nil
}

// getRbacRefs checks to see if there are any existing rbac resources which could be orphaned by this delete call
func (a *admitter) getRbacRefs(secret *corev1.Secret) ([]*rbacv1.Role, []*rbacv1.RoleBinding, error) {
	roles, err := a.roleCache.GetByIndex(roleOwnerIndex, fmt.Sprintf(ownerFormat, secret.Namespace, secret.Name))
	if err != nil {
		return nil, nil, err
	}
	roleBindings, err := a.roleBindingCache.GetByIndex(roleBindingOwnerIndex, fmt.Sprintf(ownerFormat, secret.Namespace, secret.Name))
	if err != nil {
		return nil, nil, err
	}
	return roles, roleBindings, nil
}

// isCloudCredentialSecret returns true if the secret is a cloud credential based on its
// namespace and type prefix.
func isCloudCredentialSecret(secret *corev1.Secret) bool {
	return secret.Namespace == CredentialNamespace && strings.HasPrefix(string(secret.Type), TypePrefix)
}
