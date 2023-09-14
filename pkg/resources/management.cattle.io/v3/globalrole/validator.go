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
	"golang.org/x/exp/slices"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "globalroles",
}

const roleTemplateClusterContext = "cluster"

// NewValidator returns a new validator used for validation globalRoles.
func NewValidator(ruleResolver validation.AuthorizationRuleResolver, grbResolver *resolvers.GRBClusterRuleResolver) *Validator {
	return &Validator{
		admitter: admitter{
			resolver:    ruleResolver,
			grbResolver: grbResolver,
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
	resolver    validation.AuthorizationRuleResolver
	grbResolver *resolvers.GRBClusterRuleResolver
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
		if isMetaOnlyChange(oldGR, newGR) {
			// if this change only affects metadata, don't validate any further
			// this allows users with the appropriate permissions to manage labels/annotations/finalizers
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

	err = a.validateFields(oldGR, newGR, fldPath)
	if err != nil {
		if errors.As(err, admission.Ptr(new(field.Error))) {
			return admission.ResponseBadRequest(err.Error()), nil
		}
		return nil, err
	}

	// check for escalation separately between cluster permissions and global permissions to prevent crossover
	clusterRules, err := a.grbResolver.GlobalRoleResolver.ClusterRulesFromRole(newGR)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve rules for new global role: %w", err)
	}
	err = auth.ConfirmNoEscalation(request, clusterRules, "", a.grbResolver)
	if err != nil {
		return admission.ResponseFailedEscalation(err.Error()), nil
	}

	rules := a.grbResolver.GlobalRoleResolver.GlobalRulesFromRole(newGR)

	err = auth.ConfirmNoEscalation(request, rules, "", a.resolver)
	if err != nil {
		return admission.ResponseFailedEscalation(err.Error()), nil
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

// validateFields validates fields validates that the defined rules all have verbs and check the inheritedClusterRoles.
func (a *admitter) validateFields(oldRole, newRole *v3.GlobalRole, fldPath *field.Path) error {
	if err := common.CheckForVerbs(newRole.Rules); err != nil {
		return field.Required(fldPath.Child("rules"), err.Error())
	}
	return a.validateInheritedClusterRoles(oldRole, newRole, fldPath.Child("inheritedClusterRoles"))
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
		currentRoleTemplates, err = a.grbResolver.GlobalRoleResolver.GetRoleTemplatesForGlobalRole(newGR)
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
	defer func() {
		oldRole.NewUserDefault = origDefault
	}()
	oldRole.NewUserDefault = newRole.NewUserDefault

	if !grContentEqual(oldRole, newRole) {
		return field.Forbidden(fldPath, "updates to builtIn GlobalRoles for fields other than 'newUserDefault' are forbidden")
	}
	return nil
}

// isMetaOnlyChange checks if old and new are deep equal in all fields except metadata and typemeta. Will return false on a
// non-effectual change.
func isMetaOnlyChange(oldGR *v3.GlobalRole, newGR *v3.GlobalRole) bool {
	// if the metadata between old/new hasn't changed, then this isn't a metadata only change
	if grMetaEqual(oldGR, newGR) {
		return false
	}

	return grContentEqual(oldGR, newGR)
}

func grMetaEqual(oldGR *v3.GlobalRole, newGR *v3.GlobalRole) bool {
	if oldGR == newGR {
		// same pointer or both objects are nil
		return true
	}
	if oldGR == nil || newGR == nil {
		// one object is nil and the other is not.
		return false
	}
	return reflect.DeepEqual(oldGR.ObjectMeta, newGR.ObjectMeta)
}

// grContentEqual checks if two globalRoles have equivalent content (all fields excluding metadata && typeMeta).
// this function is used instead of reflect.DeepEqual since it is less costly and faster.
// this function ignores the typeMeta field of the object.
func grContentEqual(oldGR *v3.GlobalRole, newGR *v3.GlobalRole) bool {
	if oldGR == newGR {
		// same pointer or both objects are nil
		return true
	}
	if oldGR == nil || newGR == nil {
		// one object is nil and the other is not.
		return false
	}

	return oldGR.DisplayName == newGR.DisplayName &&
		oldGR.Description == newGR.Description &&
		oldGR.NewUserDefault == newGR.NewUserDefault &&
		oldGR.Builtin == newGR.Builtin &&
		slices.Equal(oldGR.InheritedClusterRoles, newGR.InheritedClusterRoles) &&
		policyRulesEqual(oldGR.Rules, newGR.Rules)
}

// policyRulesEqual checks for equivalence between two list of policy rules.
// This function considers both empty list and nil list as equivalent.
func policyRulesEqual(rules1, rules2 []rbacv1.PolicyRule) bool {
	return slices.EqualFunc(rules1, rules2, rulesAreEqual)
}

func rulesAreEqual(rule1, rule2 rbacv1.PolicyRule) bool {
	return slices.Equal(rule1.Verbs, rule2.Verbs) &&
		slices.Equal(rule1.APIGroups, rule2.APIGroups) &&
		slices.Equal(rule1.Resources, rule2.Resources) &&
		slices.Equal(rule1.ResourceNames, rule2.ResourceNames) &&
		slices.Equal(rule1.NonResourceURLs, rule2.NonResourceURLs)
}
