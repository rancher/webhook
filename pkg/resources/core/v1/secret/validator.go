package secret

import (
	"encoding/json"
	"fmt"

	"github.com/rancher/webhook/pkg/admission"
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

// NewValidator creates a new secret validator which ensures secrets which own rbac objects aren't deleted with options
// to orphan those RBAC resources.
func NewValidator(roleCache v1.RoleCache, roleBindingCache v1.RoleBindingCache) *Validator {
	roleCache.AddIndexer(roleOwnerIndex, func(obj *rbacv1.Role) ([]string, error) {
		return secretOwnerIndexer(obj.ObjectMeta), nil
	})
	roleBindingCache.AddIndexer(roleBindingOwnerIndex, func(obj *rbacv1.RoleBinding) ([]string, error) {
		return secretOwnerIndexer(obj.ObjectMeta), nil
	})
	return &Validator{
		admitter: admitter{
			roleCache:        roleCache,
			roleBindingCache: roleBindingCache,
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
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Delete}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	validatingWebhook := admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope, v.Operations())
	validatingWebhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNone)
	return []admissionregistrationv1.ValidatingWebhook{*validatingWebhook}
}

// Admitters returns the admitter objects used to validate secrets.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
	roleCache        v1.RoleCache
	roleBindingCache v1.RoleBindingCache
}

// Admit is the entrypoint for the validator. Admit will return an error if it is unable to process the request.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("secret Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	var deleteOpts metav1.DeleteOptions
	err := json.Unmarshal(request.Options.Raw, &deleteOpts)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal delete options %w", err)
	}
	hasOrphanDependents := deleteOpts.OrphanDependents != nil && *deleteOpts.OrphanDependents
	hasOrphanPolicy := deleteOpts.PropagationPolicy != nil && *deleteOpts.PropagationPolicy == metav1.DeletePropagationOrphan
	// we are only concerned with requests that attempt to orphan resources
	if !hasOrphanDependents && !hasOrphanPolicy {
		return admission.ResponseAllowed(), nil
	}
	secret, err := objectsv1.SecretFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to read secret from request: %w", err)
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
