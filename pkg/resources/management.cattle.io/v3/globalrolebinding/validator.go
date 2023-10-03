// Package globalrolebinding holds admission logic for the v3 management.cattle.io.globalrolebindings CRD.
package globalrolebinding

import (
	"errors"
	"fmt"
	"strings"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resolvers"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	rbacvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/trace"
)

var (
	gvr = schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "globalrolebindings",
	}
	globalRoleGvr = schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "globalroles",
	}
)

const bindVerb = "bind"

// NewValidator returns a new validator for GlobalRoleBindings.
func NewValidator(resolver rbacvalidation.AuthorizationRuleResolver, grbResolver *resolvers.GRBClusterRuleResolver,
	sar authorizationv1.SubjectAccessReviewInterface) *Validator {
	return &Validator{
		admitter: admitter{
			resolver:    resolver,
			grbResolver: grbResolver,
			sar:         sar,
		},
	}
}

// Validator is used to validate operations to GlobalRoleBindings.
type Validator struct {
	admitter admitter
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope, v.Operations())}
}

// Admitters returns the admitter objects used to validate globalRoleBindings.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
	resolver    rbacvalidation.AuthorizationRuleResolver
	grbResolver *resolvers.GRBClusterRuleResolver
	sar         authorizationv1.SubjectAccessReviewInterface
}

// Admit handles the webhook admission request sent to this webhook.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("globalRoleBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldGRB, newGRB, err := objectsv3.GlobalRoleBindingOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s from request: %w", gvr.Resource, err)
	}

	// if the grb is being deleted don't enforce integrity checks
	if request.Operation == admissionv1.Update && newGRB.DeletionTimestamp != nil {
		return admission.ResponseAllowed(), nil
	}

	fldPath := field.NewPath(gvr.Resource)
	// Pull the global role for validation.
	globalRole, err := a.grbResolver.GlobalRoleResolver.GlobalRoleCache().Get(newGRB.GlobalRoleName)
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get GlobalRole '%s': %w", newGRB.Name, err)
		}
		fieldErr := field.NotFound(fldPath.Child("globalRoleName"), newGRB.GlobalRoleName)
		return admission.ResponseBadRequest(fieldErr.Error()), nil
	}

	switch request.Operation {
	case admissionv1.Update:
		err = validateUpdateFields(oldGRB, newGRB, fldPath)
	case admissionv1.Create:
		err = a.validateCreate(newGRB, globalRole, fldPath)
	default:
		return nil, fmt.Errorf("%s operation %v: %w", gvr.Resource, request.Operation, admission.ErrUnsupportedOperation)
	}

	if err != nil {
		if errors.As(err, admission.Ptr(new(field.Error))) {
			return admission.ResponseBadRequest(err.Error()), nil
		}
		return nil, err
	}

	clusterRules, err := a.grbResolver.GlobalRoleResolver.ClusterRulesFromRole(globalRole)
	if err != nil {
		if apierrors.IsNotFound(err) {
			reason := fmt.Sprintf("at least one roleTemplate was not found %s", err.Error())
			return admission.ResponseBadRequest(reason), nil
		}
		return nil, fmt.Errorf("unable to get global rules from role %s: %w", globalRole.Name, err)
	}
	hasBind, err := a.isRulesAllowed(request, clusterRules, globalRole.Name, a.grbResolver)
	if err != nil {
		return admission.ResponseFailedEscalation(err.Error()), nil
	}
	if hasBind {
		// user has the bind verb, no need to check global permissions
		return admission.ResponseAllowed(), nil
	}

	rules := a.grbResolver.GlobalRoleResolver.GlobalRulesFromRole(globalRole)
	_, err = a.isRulesAllowed(request, rules, globalRole.Name, a.resolver)
	// don't need to check if this request was allowed due to the bind verb since this is the last permission check
	// if others are added in the future a short-circuit here will be needed like for the clusterRules
	if err != nil {
		return admission.ResponseFailedEscalation(err.Error()), nil
	}
	return admission.ResponseAllowed(), nil
}

// isRulesAllowed checks if the use of requested rules are allowed by the givenResolver for a given request/user
// returns an error if the user failed an escalation check, and nil if the request was allowed. Also returns a bool
// indicating if the allow was due to the user having the bind verb
func (a *admitter) isRulesAllowed(request *admission.Request, rules []rbacv1.PolicyRule, grName string, resolver rbacvalidation.AuthorizationRuleResolver) (bool, error) {
	err := auth.ConfirmNoEscalation(request, rules, "", resolver)
	if err != nil {
		hasBind, bindErr := auth.RequestUserHasVerb(request, globalRoleGvr, a.sar, bindVerb, grName, "")
		if bindErr != nil {
			logrus.Warnf("Failed to check for the 'bind' verb on GlobalRoles: %v", bindErr)
			return false, err
		}
		if hasBind {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

// validUpdateFields checks if the fields being changed are valid update fields.
func validateUpdateFields(oldBinding, newBinding *v3.GlobalRoleBinding, fldPath *field.Path) error {
	var err error
	const immutable = "field is immutable"
	switch {
	case newBinding.UserName != oldBinding.UserName:
		err = field.Invalid(fldPath.Child("userName"), newBinding.UserName, immutable)
	case newBinding.GroupPrincipalName != oldBinding.GroupPrincipalName:
		err = field.Invalid(fldPath.Child("groupPrincipalName"), newBinding.GroupPrincipalName, immutable)
	case newBinding.GlobalRoleName != oldBinding.GlobalRoleName:
		err = field.Invalid(fldPath.Child("globalRoleName"), newBinding.GlobalRoleName, immutable)
	}

	return err
}

// validateCreateFields checks if all required fields are present and valid.
func (a *admitter) validateCreate(newBinding *v3.GlobalRoleBinding, globalRole *v3.GlobalRole, fldPath *field.Path) error {
	switch {
	case newBinding.UserName != "" && newBinding.GroupPrincipalName != "":
		return field.Forbidden(fldPath, "bindings can not set both userName and groupPrincipalName")
	case newBinding.UserName == "" && newBinding.GroupPrincipalName == "":
		return field.Required(fldPath, "bindings must have either userName or groupPrincipalName set")
	}

	return a.validateGlobalRole(globalRole, fldPath)
}

// validateGlobalRole validates that the attached global role isn't trying to use a locked RoleTemplate.
func (a *admitter) validateGlobalRole(globalRole *v3.GlobalRole, fieldPath *field.Path) error {
	roleTemplates, err := a.grbResolver.GlobalRoleResolver.GetRoleTemplatesForGlobalRole(globalRole)
	if err != nil {
		if apierrors.IsNotFound(err) {
			reason := fmt.Sprintf("unable to find all roleTemplates %s", err.Error())
			return field.Invalid(fieldPath, "", reason)
		}
		return fmt.Errorf("unable to get role templates for global role %s: %w", globalRole.Name, err)
	}
	var lockedRTNames []string
	for _, roleTemplate := range roleTemplates {
		if roleTemplate.Locked {
			lockedRTNames = append(lockedRTNames, roleTemplate.Name)
		}
	}
	if len(lockedRTNames) > 0 {
		joinedNames := strings.Join(lockedRTNames, ", ")
		reason := fmt.Sprintf("global role inherits roleTemplate(s) %s which is locked", joinedNames)
		return field.Invalid(fieldPath.Child("globalRoleName"), globalRole.Name, reason)
	}
	return nil
}
