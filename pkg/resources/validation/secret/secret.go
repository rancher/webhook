package secret

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	v1 "github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1"
	"github.com/rancher/wrangler/pkg/webhook"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/trace"
)

const (
	roleOwnerIndex        = "webhook.cattle.io/role-owner-index"
	roleBindingOwnerIndex = "webhook.cattle.io/role-binding-owner-index"
	secretKind            = "Secret"
	secretAPIVersion      = "v1"
	ownerFormat           = "%s/%s"
	logPrefix             = "validator/corev1/secret"
)

// Validator implements admission.ValidatingAdmissionWebhook.
type Validator struct {
	roleCache        v1.RoleCache
	roleBindingCache v1.RoleBindingCache
}

// NewValidator creates a new secret validator which ensures secrets which own rbac objects aren't deleted with options
// to oprhan those RBAC resources
func NewValidator(roleCache v1.RoleCache, roleBindingCache v1.RoleBindingCache) *Validator {
	roleCache.AddIndexer(roleOwnerIndex, func(obj *rbacv1.Role) ([]string, error) {
		return secretOwnerIndexer(obj.ObjectMeta), nil
	})
	roleBindingCache.AddIndexer(roleBindingOwnerIndex, func(obj *rbacv1.RoleBinding) ([]string, error) {
		return secretOwnerIndexer(obj.ObjectMeta), nil
	})
	return &Validator{
		roleCache:        roleCache,
		roleBindingCache: roleBindingCache,
	}
}

// secretOwnerIndexer indexes an object based on all owning secrets.
func secretOwnerIndexer(objMeta metav1.ObjectMeta) []string {
	var owningSecrets []string
	for _, owner := range objMeta.OwnerReferences {
		if owner.APIVersion == secretAPIVersion && owner.Kind == secretKind {
			owningSecrets = append(owningSecrets, fmt.Sprintf(ownerFormat, objMeta.Namespace, owner.Name))
		}
	}
	return owningSecrets
}

func (v *Validator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("secret Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	if request.Operation != admissionv1.Delete {
		// only handle delete requests - other request types don't need to be validated by this webhook
		response.Allowed = true
		return nil
	}
	var deleteOpts metav1.DeleteOptions
	err := json.Unmarshal(request.Options.Raw, &deleteOpts)
	if err != nil {
		return fmt.Errorf("unable to unmarshal delete options %w", err)
	}
	hasOrphanDependents := deleteOpts.OrphanDependents != nil && *deleteOpts.OrphanDependents
	hasOrphanPolicy := deleteOpts.PropagationPolicy != nil && *deleteOpts.PropagationPolicy == metav1.DeletePropagationOrphan
	// we are only concerned with requests that attempt to orphan resources
	if !hasOrphanDependents && !hasOrphanPolicy {
		response.Allowed = true
		return nil

	}
	rawSecret, err := request.DecodeOldObject()
	if err != nil {
		return fmt.Errorf("unable to read secret from request: %w", err)
	}
	secret, ok := rawSecret.(*corev1.Secret)
	if !ok {
		return fmt.Errorf("object from request was not a secret")
	}
	roles, roleBindings, err := v.getRbacRefs(secret)
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
	if err != nil {
		return fmt.Errorf("unable to determine if secret has rbac refs: %w", err)
	}
	// requests which orphan non-rbac resources are allowed
	if len(roles) == 0 && len(roleBindings) == 0 {
		response.Allowed = true
		return nil
	}
	// secret orphans rbac resources, deny the request
	response.Result = &metav1.Status{
		Status:  "Failure",
		Message: "A secret which owns RBAC objects cannot be deleted with OrphanDependents: true or PropagationPolicy: Orphan",
		Reason:  metav1.StatusReasonBadRequest,
		Code:    http.StatusBadRequest,
	}
	response.Allowed = false
	return nil

}

// getRbacRefs checks to see if there are any existing rbac resources which could be orphaned by this delete call
func (v *Validator) getRbacRefs(secret *corev1.Secret) ([]*rbacv1.Role, []*rbacv1.RoleBinding, error) {
	roles, err := v.roleCache.GetByIndex(roleOwnerIndex, fmt.Sprintf(ownerFormat, secret.Namespace, secret.Name))
	if err != nil {
		return nil, nil, err
	}
	roleBindings, err := v.roleBindingCache.GetByIndex(roleBindingOwnerIndex, fmt.Sprintf(ownerFormat, secret.Namespace, secret.Name))
	if err != nil {
		return nil, nil, err
	}
	return roles, roleBindings, nil
}
