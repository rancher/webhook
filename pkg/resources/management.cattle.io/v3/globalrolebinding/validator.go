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
	"github.com/rancher/webhook/pkg/resources/common"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
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
func NewValidator(resolver rbacvalidation.AuthorizationRuleResolver, grbResolvers *resolvers.GRBRuleResolvers,
	sar authorizationv1.SubjectAccessReviewInterface, grResolver *auth.GlobalRoleResolver) *Validator {
	return &Validator{
		admitter: admitter{
			resolver:     resolver,
			grbResolvers: grbResolvers,
			sar:          sar,
			grResolver:   grResolver,
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
	resolver     rbacvalidation.AuthorizationRuleResolver
	grbResolvers *resolvers.GRBRuleResolvers
	grResolver   *auth.GlobalRoleResolver
	sar          authorizationv1.SubjectAccessReviewInterface
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
	globalRole, err := a.grResolver.GlobalRoleCache().Get(newGRB.GlobalRoleName)
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

	fwResourceRules := a.grResolver.FleetWorkspacePermissionsResourceRulesFromRole(globalRole)
	fwWorkspaceVerbsRules := a.grResolver.FleetWorkspacePermissionsWorkspaceVerbsFromRole(globalRole)
	globalRules := a.grResolver.GlobalRulesFromRole(globalRole)
	clusterRules, err := a.grResolver.ClusterRulesFromRole(globalRole)
	if err != nil {
		if apierrors.IsNotFound(err) {
			reason := fmt.Sprintf("at least one roleTemplate was not found %s", err.Error())
			return admission.ResponseBadRequest(reason), nil
		}
		return nil, fmt.Errorf("unable to get global rules from role %s: %w", globalRole.Name, err)
	}

	// Collect all escalations to return to user
	var returnError error
	bindChecker := common.NewCachedVerbChecker(request, globalRole.Name, a.sar, globalRoleGvr, bindVerb)

	returnError = bindChecker.IsRulesAllowed(clusterRules, a.grbResolvers.ICRResolver, "")
	if bindChecker.HasVerb() {
		return admission.ResponseAllowed(), nil
	}
	returnError = errors.Join(returnError, bindChecker.IsRulesAllowed(globalRules, a.resolver, ""))
	if bindChecker.HasVerb() {
		return admission.ResponseAllowed(), nil
	}
	returnError = errors.Join(returnError, bindChecker.IsRulesAllowed(fwResourceRules, a.grbResolvers.FWRulesResolver, ""))
	if bindChecker.HasVerb() {
		return admission.ResponseAllowed(), nil
	}
	returnError = errors.Join(returnError, bindChecker.IsRulesAllowed(fwWorkspaceVerbsRules, a.grbResolvers.FWVerbsResolver, ""))
	if bindChecker.HasVerb() {
		return admission.ResponseAllowed(), nil
	}

	for namespace, rules := range globalRole.NamespacedRules {
		returnError = errors.Join(returnError, bindChecker.IsRulesAllowed(rules, a.resolver, namespace))
		if bindChecker.HasVerb() {
			return admission.ResponseAllowed(), nil
		}
	}
	if returnError != nil {
		return admission.ResponseFailedEscalation(fmt.Sprintf("errors due to escalation: %v", returnError)), nil
	}

	return admission.ResponseAllowed(), nil
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
	roleTemplates, err := a.grResolver.GetRoleTemplatesForGlobalRole(globalRole)
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
