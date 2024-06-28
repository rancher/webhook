package secret

import (
	"fmt"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	"github.com/rancher/webhook/pkg/patch"
	v1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/rbac/v1"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

const (
	mutatorRoleBindingOwnerIndex = "webhook.cattle.io/role-binding-index"
	secretKind                   = "Secret"
	ownerFormat                  = "%s/%s"
)

var gvr = corev1.SchemeGroupVersion.WithResource("secrets")

// Mutator implements admission.MutatingAdmissionWebhook.
type Mutator struct {
	roleController        v1.RoleController
	roleBindingController v1.RoleBindingController
}

// NewMutator returns a new mutator which mutates secret objects, and related resources
func NewMutator(roleController v1.RoleController, roleBindingController v1.RoleBindingController) *Mutator {
	roleBindingController.Cache().AddIndexer(mutatorRoleBindingOwnerIndex, roleBindingIndexer)
	return &Mutator{
		roleController:        roleController,
		roleBindingController: roleBindingController,
	}

}

// roleBindingIndexer indexes an object based on all owning secrets.
func roleBindingIndexer(roleBinding *rbacv1.RoleBinding) ([]string, error) {
	// only looking for roleBindings targeting roles
	if roleBinding.RoleRef.Kind != "Role" {
		return nil, nil
	}
	var owningSecrets []string
	for _, owner := range roleBinding.OwnerReferences {
		if owner.APIVersion == corev1.SchemeGroupVersion.String() && owner.Kind == secretKind {
			owningSecrets = append(owningSecrets, fmt.Sprintf(ownerFormat, roleBinding.Namespace, owner.Name))
		}
	}
	return owningSecrets, nil
}

// GVR returns the GroupVersionKind for this CRD.
func (m *Mutator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this mutator.
func (m *Mutator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Delete}
}

// MutatingWebhook returns the MutatingWebhook used for this CRD.
func (m *Mutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.MutatingWebhook {
	mutatingWebhook := admission.NewDefaultMutatingWebhook(m, clientConfig, admissionregistrationv1.NamespacedScope, m.Operations())
	mutatingWebhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNoneOnDryRun)
	mutatingWebhook.TimeoutSeconds = admission.Ptr(int32(15))
	return []admissionregistrationv1.MutatingWebhook{*mutatingWebhook}
}

// Admit is the entrypoint for the mutator. Admit will return an error if it unable to process the request.
func (m *Mutator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if request.DryRun != nil && *request.DryRun {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}

	listTrace := trace.New("secret Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	secret, err := objectsv1.SecretFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}
	switch request.Operation {
	case admissionv1.Create:
		return m.admitCreate(secret, request)
	case admissionv1.Delete:
		return m.admitDelete(secret)
	default:
		return nil, fmt.Errorf("operation type %q not handled", request.Operation)
	}
}

func (m *Mutator) admitCreate(secret *corev1.Secret, request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if secret.Type != "provisioning.cattle.io/cloud-credential" {
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}

	logrus.Debugf("[secret-mutation] adding creatorID %v to secret: %v", request.UserInfo.Username, secret.Name)
	newSecret := secret.DeepCopy()

	if newSecret.Annotations == nil {
		newSecret.Annotations = make(map[string]string)
	}

	newSecret.Annotations[auth.CreatorIDAnn] = request.UserInfo.Username
	response := &admissionv1.AdmissionResponse{}
	if err := patch.CreatePatch(request.Object.Raw, newSecret, response); err != nil {
		return nil, fmt.Errorf("failed to create patch: %w", err)
	}
	response.Allowed = true
	return response, nil
}

// admitDelete checks if there are any roleBindings owned by this secret which provide access to a role granting access to this secret.
// If yes, it redacts the role, so that it only grants a deletion permission. This handles cases where users were given owner access to an individual secret
// through a controller (like cloud-credentials), and delete the secret but keep the rbac
func (m *Mutator) admitDelete(secret *corev1.Secret) (*admissionv1.AdmissionResponse, error) {
	roleBindings, err := m.roleBindingController.Cache().GetByIndex(mutatorRoleBindingOwnerIndex, fmt.Sprintf(ownerFormat, secret.Namespace, secret.Name))
	if err != nil {
		return nil, fmt.Errorf("unable to determine if secret %s/%s has rbac references: %w", secret.Namespace, secret.Name, err)
	}
	for _, roleBinding := range roleBindings {
		role, err := m.roleController.Cache().Get(roleBinding.Namespace, roleBinding.RoleRef.Name)
		if err != nil {
			// if the role doesn't exist, don't need to de-power the role
			if apierrors.IsNotFound(err) {
				continue
			}
			return nil, fmt.Errorf("unable to evaluate role %s/%s granted by binding %s/%s owned by the secret: %w", role.Namespace, role.Name, roleBinding.Namespace, roleBinding.Name, err)
		}
		rules, amended := amendRulesToOnlyPermitDelete(role.Rules, secret.Name)
		if amended {
			role.Rules = rules
			_, err = m.roleController.Update(role)
			// role may have been deleted by this point, if so, ignore the error
			if err != nil && !apierrors.IsNotFound(err) {
				return nil, fmt.Errorf("unable to revoke permissions on role %s/%s granted by binding %s/%s owned by the secret: %w", role.Namespace, role.Name, roleBinding.Namespace, roleBinding.Name, err)
			}
		}

	}
	return admission.ResponseAllowed(), nil
}

// amendRulesToOnlyPermitDelete changes rules which grant specific access to the secret identified by secretName so that they only give delete access
// this function specifically targets rules which have a form used by rancher in granting access to cloud credentials, and omits other types of rules
// such as * verbs on * resources in * groups which can give access to this secret, but aren't of the form used by the cloud credential logic.
func amendRulesToOnlyPermitDelete(rules []rbacv1.PolicyRule, secretName string) ([]rbacv1.PolicyRule, bool) {
	// we only want the specific rule which grants get level access to this specific resource. The form is constricted enough
	// for this to catch these rules
	amended := false
	for i, rule := range rules {
		// only targeting rules with a single api group "" or *
		apiGroupMatches := len(rule.APIGroups) == 1 && (rule.APIGroups[0] == "" || rule.APIGroups[0] == "*")
		resourceMatches := len(rule.Resources) == 1 && rule.Resources[0] == "secrets"
		nameMatches := len(rule.ResourceNames) == 1 && rule.ResourceNames[0] == secretName
		hasGet := false
		for _, verb := range rule.Verbs {
			if verb == "get" || verb == "*" {
				hasGet = true
				break
			}
		}
		if apiGroupMatches && resourceMatches && nameMatches && hasGet {
			amended = true
			rule.Verbs = []string{"delete"}
			rules[i] = rule
		}

	}
	return rules, amended
}
