package secret

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha3"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/rancher/webhook/pkg/admission"
	ctrlv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	"github.com/rancher/webhook/pkg/patch"
	"github.com/rancher/webhook/pkg/resources/common"
	v1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/rbac/v1"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

const (
	mutatorRoleBindingOwnerIndex = "webhook.cattle.io/role-binding-index"
	secretKind                   = "Secret"
	ownerFormat                  = "%s/%s"
	localUserPasswordsNamespace  = "cattle-local-user-passwords"
	passwordHashAnnotation       = "cattle.io/password-hash"
	pbkdf2sha3512Hash            = "pbkdf2sha3512"
	iterations                   = 210000
	keyLength                    = 32
	passwordMinLengthSetting     = "password-min-length"
)

type passwordHasher func(password string) ([]byte, []byte, error)

var gvr = corev1.SchemeGroupVersion.WithResource("secrets")

// Mutator implements admission.MutatingAdmissionWebhook.
type Mutator struct {
	roleController        v1.RoleController
	roleBindingController v1.RoleBindingController
	hasher                passwordHasher
	settingCache          ctrlv3.SettingCache
	userCache             ctrlv3.UserCache
}

// NewMutator returns a new mutator which mutates secret objects, and related resources
func NewMutator(roleController v1.RoleController, roleBindingController v1.RoleBindingController, settingCache ctrlv3.SettingCache, userCache ctrlv3.UserCache) *Mutator {
	roleBindingController.Cache().AddIndexer(mutatorRoleBindingOwnerIndex, roleBindingIndexer)
	return &Mutator{
		roleController:        roleController,
		roleBindingController: roleBindingController,
		settingCache:          settingCache,
		userCache:             userCache,
		hasher:                hashPassword,
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
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Delete, admissionregistrationv1.Update}
}

// MutatingWebhook returns the MutatingWebhook used for this CRD.
func (m *Mutator) MutatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.MutatingWebhook {
	mutatingWebhook := admission.NewDefaultMutatingWebhook(m, clientConfig, admissionregistrationv1.NamespacedScope, m.Operations())
	mutatingWebhook.SideEffects = admission.Ptr(admissionregistrationv1.SideEffectClassNoneOnDryRun)
	mutatingWebhook.TimeoutSeconds = admission.Ptr(int32(15))
	mutatingWebhook.MatchConditions = []admissionregistrationv1.MatchCondition{
		{
			Name:       "filter-by-secret-type-cloud-credential",
			Expression: `request.operation == 'DELETE' || (object != null && object.type == "provisioning.cattle.io/cloud-credential" && request.operation == 'CREATE') || (object != null && object.metadata.namespace == "` + localUserPasswordsNamespace + `")`,
		},
	}

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
	if request.Namespace == localUserPasswordsNamespace {
		return m.admitLocalUserPassword(secret, request)
	}
	switch request.Operation {
	case admissionv1.Create:
		return m.admitCreate(secret, request)
	case admissionv1.Delete:
		return m.admitDelete(secret)
	case admissionv1.Update:
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	default:
		return nil, fmt.Errorf("operation type %q not handled", request.Operation)
	}
}

func (m *Mutator) admitCreate(secret *corev1.Secret, request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	logrus.Debugf("[secret-mutation] adding creatorID %v to secret: %v", request.UserInfo.Username, secret.Name)
	newSecret := secret.DeepCopy()

	common.SetCreatorIDAnnotation(request, newSecret)

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

// admitLocalUserPassword handle the secrets that contains the local user passwords, which are stored in the cattle-local-user-passwords namespace.
// If the annotation ccattle.io/password-hash is not present in the secret, the webhook will encrypt it using pbkdf2. The secret is mutated to include the hashed password, the salt and the user as owner reference.
func (m *Mutator) admitLocalUserPassword(secret *corev1.Secret, request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	if secret.Annotations[passwordHashAnnotation] == pbkdf2sha3512Hash ||
		request.Operation == admissionv1.Delete {
		// no need to do anything if password is encrypted or is a delete operation.
		return &admissionv1.AdmissionResponse{
			Allowed: true,
		}, nil
	}
	user, err := m.userCache.Get(secret.Name)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return admission.ResponseBadRequest(fmt.Sprintf("user %s does not exist. User must be created before the secret", secret.Name)), nil
		}
		return nil, err
	}
	password := string(secret.Data["password"])
	passwordMinLength, err := m.getPasswordMinLength()
	if err != nil {
		return nil, err
	}
	if utf8.RuneCountInString(password) < passwordMinLength {
		return admission.ResponseBadRequest(fmt.Sprintf("password must be at least %v characters", passwordMinLength)), nil
	}
	if request.UserInfo.Username == password {
		return admission.ResponseBadRequest("password cannot be the same as username"), nil
	}
	hashedPassword, salt, err := m.hasher(password)
	if err != nil {
		return nil, err
	}
	response := &admissionv1.AdmissionResponse{}
	newSecret := secret.DeepCopy()
	if newSecret.Annotations == nil {
		newSecret.Annotations = map[string]string{}
	}
	newSecret.Annotations[passwordHashAnnotation] = pbkdf2sha3512Hash
	newSecret.Data["password"] = hashedPassword
	newSecret.Data["salt"] = salt
	newSecret.OwnerReferences = []metav1.OwnerReference{
		{
			APIVersion: user.APIVersion,
			Kind:       user.Kind,
			Name:       user.Name,
			UID:        user.UID,
		},
	}
	if err := patch.CreatePatch(request.Object.Raw, newSecret, response); err != nil {
		return nil, fmt.Errorf("failed to create patch: %w", err)
	}
	response.Allowed = true

	return response, nil
}

// getPasswordMinLength gets the min length for passwords from the settings.
func (m *Mutator) getPasswordMinLength() (int, error) {
	setting, err := m.settingCache.Get("password-min-length")
	if err != nil {
		return 0, err
	}
	var passwordMinLength int
	if setting.Value != "" {
		passwordMinLength, err = strconv.Atoi(setting.Value)
		if err != nil {
			return 0, err
		}
	} else {
		passwordMinLength, err = strconv.Atoi(setting.Default)
		if err != nil {
			return 0, err
		}
	}

	return passwordMinLength, nil
}

// hashPassword hashes the password using pbkdf2.
func hashPassword(password string) ([]byte, []byte, error) {
	salt := make([]byte, 32)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	passwordHashed, err := pbkdf2.Key(sha3.New512, password, salt, iterations, keyLength)
	if err != nil {
		return nil, nil, err
	}

	return passwordHashed, salt, nil
}
