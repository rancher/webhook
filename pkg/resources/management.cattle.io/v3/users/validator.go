package users

import (
	"context"
	"fmt"
	"strings"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	controllerv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resources/common"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/apiserver/pkg/authentication/user"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/ptr"
)

var (
	gvr = schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "users",
	}
	manageUsersVerb = "manage-users"
)

type admitter struct {
	resolver           validation.AuthorizationRuleResolver
	sar                authorizationv1.SubjectAccessReviewInterface
	userAttributeCache controllerv3.UserAttributeCache
	userCache          controllerv3.UserCache
	featureCache       controllerv3.FeatureCache
	authConfigCache    controllerv3.AuthConfigCache
}

// Validator validates users.
type Validator struct {
	admitter admitter
}

// NewValidator returns a new Validator instance.
func NewValidator(
	userAttributeCache controllerv3.UserAttributeCache,
	sar authorizationv1.SubjectAccessReviewInterface,
	defaultResolver validation.AuthorizationRuleResolver,
	userCache controllerv3.UserCache,
	featureCache controllerv3.FeatureCache,
	authConfigCache controllerv3.AuthConfigCache,
) *Validator {
	return &Validator{
		admitter: admitter{
			resolver:           defaultResolver,
			userAttributeCache: userAttributeCache,
			sar:                sar,
			userCache:          userCache,
			featureCache:       featureCache,
			authConfigCache:    authConfigCache,
		},
	}
}

// GVR returns the GroupVersionResource.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by the validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update, admissionregistrationv1.Delete}
}

func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{
		*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope, v.Operations()),
	}
}

// Admitters returns the admitter objects.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	oldUser, newUser, err := objectsv3.UserOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get current User from request: %w", err)
	}

	if request.Operation == admissionv1.Create {
		response, err := a.checkLocalUser("create", newUser)
		if response != nil || err != nil {
			return response, err
		}

		if newUser.Username != "" {
			if resp, err := a.checkUsernameUniqueness(newUser.Username); err != nil || resp != nil {
				return resp, err
			}
		}
		return &admissionv1.AdmissionResponse{Allowed: true}, nil
	}

	// Check manage-users verb before Update/Delete operation checks so that the bypass
	// applies to checkLocalUser, allowing admins to update or delete local users for
	// migration cleanup. Create is intentionally excluded — the feature always blocks
	// creation of local users regardless of the privilege.
	hasManageUsers, err := auth.RequestUserHasVerb(request, gvr, a.sar, manageUsersVerb, "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to check if requester has manage-users verb: %w", err)
	}

	fieldPath := field.NewPath("user")
	if request.Operation == admissionv1.Update {
		if !hasManageUsers {
			response, err := a.checkLocalUser("update", newUser)
			if response != nil || err != nil {
				return response, err
			}
		}

		if err := validateUpdateFields(oldUser, newUser, fieldPath); err != nil {
			return admission.ResponseBadRequest(err.Error()), nil
		}
		if oldUser.Username == "" && newUser.Username != "" {
			if resp, err := a.checkUsernameUniqueness(newUser.Username); err != nil || resp != nil {
				return resp, err
			}
		}

		oldUserEnabled := ptr.Deref(oldUser.Enabled, true)
		newUserEnabled := ptr.Deref(newUser.Enabled, true)

		if newUser.Name == request.UserInfo.Username && oldUserEnabled && !newUserEnabled {
			return admission.ResponseBadRequest("can't deactivate yourself"), nil
		}
	}
	if request.Operation == admissionv1.Delete {
		if !hasManageUsers {
			response, err := a.checkLocalUser("delete", oldUser)
			if response != nil || err != nil {
				return response, err
			}
		}

		if oldUser.Name == request.UserInfo.Username {
			return admission.ResponseBadRequest("can't delete yourself"), nil
		}
	}

	if hasManageUsers {
		return &admissionv1.AdmissionResponse{Allowed: true}, nil
	}

	// Need the UserAttribute to find the groups
	userAttribute, err := a.userAttributeCache.Get(oldUser.Name)
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get UserAttribute for %s: %w", oldUser.Name, err)
	}

	userInfo := &user.DefaultInfo{
		Name:   oldUser.Name,
		Groups: getGroupsFromUserAttribute(userAttribute),
	}

	// Get all rules for the user being modified
	rules, err := a.resolver.RulesFor(context.Background(), userInfo, "")
	if err != nil {
		return nil, fmt.Errorf("failed to get rules for user %v: %w", oldUser, err)
	}

	// Ensure that rules of the user being modified aren't greater than the rules of the user making the request
	err = auth.ConfirmNoEscalation(request, rules, "", a.resolver)
	if err != nil {
		return &admissionv1.AdmissionResponse{
			Allowed: false,
			Result: &metav1.Status{
				Status:  metav1.StatusFailure,
				Reason:  "ConfirmNoEscalationError",
				Message: fmt.Sprintf("request is attempting to modify user with more permissions than requester %v", err),
			},
		}, nil
	}

	return &admissionv1.AdmissionResponse{Allowed: true}, nil
}

// checkUsernameUniqueness checks if a given username is already in use by another user.
func (a *admitter) checkUsernameUniqueness(username string) (*admissionv1.AdmissionResponse, error) {
	if username == "" {
		return nil, nil
	}
	users, err := a.userCache.List(labels.Everything())
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}
	for _, user := range users {
		if user.Username == username {
			return admission.ResponseBadRequest("username already exists"), nil
		}
	}
	return nil, nil
}

// checkLocalUser rejects the admission request when the target user is a
// local-only user and the local auth provider is currently hidden.
func (a *admitter) checkLocalUser(operation string, user *v3.User) (*admissionv1.AdmissionResponse, error) {
	hidden, err := a.isLocalAuthProviderHidden()
	if err != nil {
		return nil, err
	}

	logrus.Debugf("[user-validation] %s: hide local auth = %v", operation, hidden)

	if !hidden {
		return nil, nil
	}

	logrus.Debugf("[user-validation] %s: checking user %q", operation, user.Name)

	if len(user.PrincipalIDs) == 0 {
		logrus.Debugf("[user-validation] %s: rejected local user %q (no principals)", operation, user.Name)
		return admission.ResponseBadRequest("can't " + operation + " user '" + user.Name + "' for disabled local provider"), nil
	}
	if len(user.PrincipalIDs) == 1 && strings.HasPrefix(user.PrincipalIDs[0], "local:") {
		logrus.Debugf("[user-validation] %s: rejected local user %q (local principal)", operation, user.Name)
		return admission.ResponseBadRequest("can't " + operation + " user '" + user.Name + "' for disabled local provider"), nil
	}
	// User has external principals (e.g. default admin, system user) — not local-only.
	logrus.Debugf("[user-validation] %s: continue for non-local user %q", operation, user.Name)
	return nil, nil
}

// isLocalAuthProviderHidden reports whether the local auth provider is currently
// hidden — true when the hide policy feature is enabled and at least one
// external auth provider is active.
func (a *admitter) isLocalAuthProviderHidden() (bool, error) {
	hide, err := a.isHideLocalAuthProviderPolicyEnabled()
	if err != nil {
		return false, err
	}
	if !hide {
		return false, nil
	}

	acList, err := a.authConfigCache.List(labels.Everything())
	if err != nil {
		return false, err
	}

	// Note: this checks the Enabled flag from etcd, not live provider health. If an
	// enabled external provider is unreachable (e.g. OIDC cert expired, LDAP down),
	// the webhook still treats it as active and blocks local user operations. Operators
	// must disable the external provider via Rancher UI to restore local auth access
	// during provider outages.
	externalActive := false
	for _, ac := range acList {
		if ac.Enabled && ac.Name != "local" {
			externalActive = true
			break
		}
	}

	return externalActive, nil
}

// isHideLocalAuthProviderPolicyEnabled reports whether the hide-local-auth-provider feature
// is enabled. A missing feature resource is treated as disabled — this can
// occur when a newer webhook runs against an older Rancher backend.
func (a *admitter) isHideLocalAuthProviderPolicyEnabled() (bool, error) {
	feature, err := a.featureCache.Get(common.HideLocalAuthProvider)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("failed to determine status of '%s' feature: %w", common.HideLocalAuthProvider, err)
	}

	enabled := feature.Status.Default
	if feature.Spec.Value != nil {
		enabled = *feature.Spec.Value
	}

	return enabled, nil
}

// getGroupsFromUserAttributes gets the list of group principals from a UserAttribute.
//
// Warning: UserAttributes are only updated when a user logs in, so this may not have the up to date Group Principals.
func getGroupsFromUserAttribute(userAttribute *v3.UserAttribute) []string {
	result := []string{}
	if userAttribute == nil {
		return result
	}
	for _, principals := range userAttribute.GroupPrincipals {
		for _, principal := range principals.Items {
			result = append(result, principal.Name)
		}
	}
	return result
}

// validateUpdateFields validates fields during an update. The manage-users verb does not apply to these validations.
func validateUpdateFields(oldUser, newUser *v3.User, fieldPath *field.Path) error {
	const reason = "field is immutable"
	if oldUser.Username != "" && oldUser.Username != newUser.Username {
		return field.Invalid(fieldPath.Child("username"), newUser.Username, reason)
	}
	return nil
}
