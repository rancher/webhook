// Package globalrole holds admission logic for the v3 management.cattle.io.globalroles CRD.
package globalrole

import (
	"errors"
	"fmt"
	"reflect"

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
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "globalroles",
}

const (
	roleTemplateClusterContext = "cluster"
	escalateVerb               = "escalate"
)

// NewValidator returns a new validator used for validation globalRoles.
func NewValidator(ruleResolver validation.AuthorizationRuleResolver, grbResolvers *resolvers.GRBRuleResolvers, sar authorizationv1.SubjectAccessReviewInterface, grResolver *auth.GlobalRoleResolver) *Validator {
	return &Validator{
		admitter: admitter{
			resolver:     ruleResolver,
			grResolver:   grResolver,
			grbResolvers: grbResolvers,
			sar:          sar,
		},
	}
}

// Validator implements admission.ValidatingAdmissionHandler.
type Validator struct {
	admitter admitter
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Update, admissionregistrationv1.Create, admissionregistrationv1.Delete}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope, v.Operations())}
}

// Admitters returns the admitter objects used to validate globalRoles.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
	resolver     validation.AuthorizationRuleResolver
	grResolver   *auth.GlobalRoleResolver
	grbResolvers *resolvers.GRBRuleResolvers
	sar          authorizationv1.SubjectAccessReviewInterface
}

// Admit is the entrypoint for the validator. Admit will return an error if it's unable to process the request.
// If this function is called without NewValidator(..) calls will panic.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("globalRoleValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldGR, newGR, err := objectsv3.GlobalRoleOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get GlobalRole from request: %w", err)
	}

	fldPath := field.NewPath("globalrole")
	switch request.Operation {
	case admissionv1.Delete:
		return validateDelete(oldGR, fldPath)
	case admissionv1.Update:
		if newGR.DeletionTimestamp != nil {
			// Object is in the process of being deleted, so admit it.
			// This admits update operations that happen to remove finalizers.
			// This is needed to supported the deletion of old GlobalRoles that would not pass the update check that verifies all rules have verbs.
			return admission.ResponseAllowed(), nil
		}
		fieldErr := a.validateUpdateFields(oldGR, newGR, fldPath)
		if fieldErr != nil {
			return admission.ResponseBadRequest(fieldErr.Error()), nil
		}
	case admissionv1.Create:
		fieldErr := validateCreateFields(newGR, fldPath)
		if fieldErr != nil {
			return admission.ResponseBadRequest(fieldErr.Error()), nil
		}
	default:
		return nil, fmt.Errorf("%s operation %v: %w", gvr.Resource, request.Operation, admission.ErrUnsupportedOperation)
	}

	err = a.validateInheritedClusterRoles(oldGR, newGR, fldPath.Child("inheritedClusterRoles"))
	if err != nil {
		if errors.As(err, admission.Ptr(new(field.Error))) {
			return admission.ResponseBadRequest(err.Error()), nil
		}
		return nil, err
	}

	// Validate the global and namespaced rules of the new GR
	globalRules := a.grResolver.GlobalRulesFromRole(newGR)
	returnError := common.ValidateRules(globalRules, false, fldPath.Child("rules"))

	nsrPath := fldPath.Child("namespacedRules")
	for index, rules := range newGR.NamespacedRules {
		returnError = errors.Join(returnError, common.ValidateRules(rules, true,
			nsrPath.Child(index)))
	}
	// Validate fleet workspace rules
	if newGR.InheritedFleetWorkspacePermissions != nil && newGR.InheritedFleetWorkspacePermissions.ResourceRules != nil {
		fleetWorkspaceRules := newGR.InheritedFleetWorkspacePermissions.ResourceRules
		fwrPath := fldPath.Child("inheritedFleetWorkspacePermissions").Child("resourceRules")
		returnError = errors.Join(returnError, common.ValidateRules(fleetWorkspaceRules, true, fwrPath))
	}
	// Validate fleet workspace verbs
	if newGR.InheritedFleetWorkspacePermissions != nil && newGR.InheritedFleetWorkspacePermissions.WorkspaceVerbs != nil {
		fleetWorkspaceVerbs := newGR.InheritedFleetWorkspacePermissions.WorkspaceVerbs
		if len(fleetWorkspaceVerbs) == 0 {
			returnError = errors.Join(returnError, fmt.Errorf("InheritedFleetWorkspacePermissions.WorkspaceVerbs can't be empty"))
		}
	}

	if returnError != nil {
		return admission.ResponseBadRequest(returnError.Error()), nil
	}

	// Check for escalations in the rules
	clusterRules, err := a.grResolver.ClusterRulesFromRole(newGR)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve rules for new global role: %w", err)
	}
	fwResourceRules := a.grResolver.FleetWorkspacePermissionsResourceRulesFromRole(newGR)
	fwWorkspaceVerbsRules := a.grResolver.FleetWorkspacePermissionsWorkspaceVerbsFromRole(newGR)

	escalateChecker := common.NewCachedVerbChecker(request, newGR.Name, a.sar, gvr, escalateVerb)
	returnError = errors.Join(returnError, escalateChecker.IsRulesAllowed(clusterRules, a.grbResolvers.ICRResolver, ""))
	if escalateChecker.HasVerb() {
		return admission.ResponseAllowed(), nil
	}
	returnError = errors.Join(returnError, escalateChecker.IsRulesAllowed(globalRules, a.resolver, ""))
	if escalateChecker.HasVerb() {
		return admission.ResponseAllowed(), nil
	}
	returnError = errors.Join(returnError, escalateChecker.IsRulesAllowed(fwResourceRules, a.grbResolvers.FWRulesResolver, ""))
	if escalateChecker.HasVerb() {
		return admission.ResponseAllowed(), nil
	}
	returnError = errors.Join(returnError, escalateChecker.IsRulesAllowed(fwWorkspaceVerbsRules, a.grbResolvers.FWVerbsResolver, ""))
	if escalateChecker.HasVerb() {
		return admission.ResponseAllowed(), nil
	}
	for namespace, rules := range newGR.NamespacedRules {
		returnError = errors.Join(returnError, escalateChecker.IsRulesAllowed(rules, a.resolver, namespace))
		if escalateChecker.HasVerb() {
			return admission.ResponseAllowed(), nil
		}
	}
	if returnError != nil {
		return admission.ResponseFailedEscalation(fmt.Sprintf("errors due to escalation: %v", returnError)), nil
	}

	return admission.ResponseAllowed(), nil
}

// validateDelete checks if a global role can be deleted and returns the appropriate response.
func validateDelete(oldRole *v3.GlobalRole, fldPath *field.Path) (*admissionv1.AdmissionResponse, error) {
	if oldRole.Builtin {
		return admission.ResponseBadRequest(field.Forbidden(fldPath, "cannot delete builtin GlobalRoles").Error()), nil
	}
	return admission.ResponseAllowed(), nil
}

// validateCreateFields blocks the creation of builtin globalRoles
func validateCreateFields(oldRole *v3.GlobalRole, fldPath *field.Path) *field.Error {
	if oldRole.Builtin {
		return field.Forbidden(fldPath, "cannot create builtin GlobalRoles")
	}
	return nil
}

// validateInheritedClusterRoles validates that new RoleTemplates specified by InheritedClusterRoles have a context of
// cluster and are not locked. Does NOT check for user privilege escalation. May return a field.Error indicating the
// source of the error.
func (a *admitter) validateInheritedClusterRoles(oldGR *v3.GlobalRole, newGR *v3.GlobalRole, fieldPath *field.Path) error {
	// fetch the old role templates as a map so that we can check which ones from newGR are new
	oldRoleTemplates := map[string]struct{}{}
	if oldGR != nil {
		for _, oldRT := range oldGR.InheritedClusterRoles {
			oldRoleTemplates[oldRT] = struct{}{}
		}
	}

	var currentRoleTemplates []*v3.RoleTemplate
	var err error
	if newGR != nil {
		currentRoleTemplates, err = a.grResolver.GetRoleTemplatesForGlobalRole(newGR)
		if err != nil {
			if apierrors.IsNotFound(err) {
				reason := fmt.Sprintf("unable to find all roleTemplates %s", err.Error())
				return field.Invalid(fieldPath, "", reason)
			}
			return fmt.Errorf("unable to get roleTemplates for current version of GlobalRole %s: %w", oldGR.Name, err)
		}
	}

	var newRoleTemplates []*v3.RoleTemplate
	for _, currentRT := range currentRoleTemplates {
		if _, ok := oldRoleTemplates[currentRT.Name]; !ok {
			newRoleTemplates = append(newRoleTemplates, currentRT)
		}
	}

	// if an RT is locked after the GR is created, we don't want to reject the request. But we also don't want
	// users to add a locked RT as new permissions
	for _, newRT := range newRoleTemplates {
		if newRT.Context != roleTemplateClusterContext {
			reason := fmt.Sprintf("unable to bind a roleTemplate with non-cluster context: %s", newRT.Context)
			return field.Invalid(fieldPath, newRT.Name, reason)
		}
		if newRT.Locked {
			reason := "unable to use locked roleTemplate"
			return field.Invalid(fieldPath, newRT.Name, reason)
		}
	}
	return nil
}

// validUpdateFields checks if the fields being changed are valid update fields.
func (a *admitter) validateUpdateFields(oldRole, newRole *v3.GlobalRole, fldPath *field.Path) *field.Error {
	if !oldRole.Builtin {
		if newRole.Builtin {
			return field.Forbidden(fldPath, fmt.Sprintf("cannot update non-builtIn GlobalRole %s to be builtIn", oldRole.Name))
		}
		return nil
	}

	// ignore changes to meta data and newUserDefault
	origDefault := oldRole.NewUserDefault
	origObjMeta := oldRole.ObjectMeta
	origTypeMeta := oldRole.TypeMeta
	defer func() {
		oldRole.NewUserDefault = origDefault
		oldRole.ObjectMeta = origObjMeta
		oldRole.TypeMeta = origTypeMeta
	}()
	oldRole.NewUserDefault = newRole.NewUserDefault
	oldRole.ObjectMeta = newRole.ObjectMeta
	oldRole.TypeMeta = newRole.TypeMeta

	if !reflect.DeepEqual(oldRole, newRole) {
		return field.Forbidden(fldPath, "updates to builtIn GlobalRoles for fields other than 'newUserDefault' are forbidden")
	}
	return nil
}
