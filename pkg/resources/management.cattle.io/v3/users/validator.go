package users

import (
	"context"
	"fmt"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	controllerv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
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
}

// Validator validates tokens.
type Validator struct {
	admitter admitter
}

// NewValidator returns a new Validator instance.
func NewValidator(userAttributeCache controllerv3.UserAttributeCache, sar authorizationv1.SubjectAccessReviewInterface, defaultResolver validation.AuthorizationRuleResolver, userCache controllerv3.UserCache) *Validator {
	return &Validator{
		admitter: admitter{
			resolver:           defaultResolver,
			userAttributeCache: userAttributeCache,
			sar:                sar,
			userCache:          userCache,
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

	if request.Operation == admissionv1.Create && newUser.Username != "" {
		if resp, err := a.checkUsernameUniqueness(newUser.Username); err != nil || resp != nil {
			return resp, err
		}
		return &admissionv1.AdmissionResponse{Allowed: true}, nil
	}

	fieldPath := field.NewPath("user")
	if request.Operation == admissionv1.Update {
		if err := validateUpdateFields(oldUser, newUser, fieldPath); err != nil {
			return admission.ResponseBadRequest(err.Error()), nil
		}
		if oldUser.Username == "" && newUser.Username != "" {
			if resp, err := a.checkUsernameUniqueness(newUser.Username); err != nil || resp != nil {
				return resp, err
			}
		}
	}

	// Check if requester has manage-user verb
	hasManageUsers, err := auth.RequestUserHasVerb(request, gvr, a.sar, manageUsersVerb, "", "")
	if err != nil {
		return nil, fmt.Errorf("failed to check if requester has manage-users verb: %w", err)
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
