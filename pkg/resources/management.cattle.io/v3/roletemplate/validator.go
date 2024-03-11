// Package roletemplate is used for validating roletemplate objects.
package roletemplate

import (
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
	"k8s.io/apimachinery/pkg/api/equality"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/trace"
)

const (
	clusterContext   = "cluster"
	projectContext   = "project"
	emptyContext     = ""
	rtRefIndex       = "management.cattle.io/rt-by-reference"
	rtGlobalRefIndex = "management.cattle.io/rt-by-ref-grb"
	escalateVerb     = "escalate"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "roletemplates",
}

// NewValidator returns a new validator used for validating roleTemplates.
func NewValidator(resolver validation.AuthorizationRuleResolver, roleTemplateResolver *auth.RoleTemplateResolver,
	sar authorizationv1.SubjectAccessReviewInterface, grCache controllerv3.GlobalRoleCache) *Validator {
	roleTemplateResolver.RoleTemplateCache().AddIndexer(rtRefIndex, roleTemplatesByReference)
	grCache.AddIndexer(rtGlobalRefIndex, roleTemplatesByGlobalReference)
	return &Validator{
		admitter: admitter{
			grCache:              grCache,
			resolver:             resolver,
			roleTemplateResolver: roleTemplateResolver,
			sar:                  sar,
		},
	}
}

// Validator for validating roleTemplates.
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

// Admitters returns the admitter objects used to validate RoleTemplates.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
	grCache              controllerv3.GlobalRoleCache
	resolver             validation.AuthorizationRuleResolver
	roleTemplateResolver *auth.RoleTemplateResolver
	sar                  authorizationv1.SubjectAccessReviewInterface
}

// Admit handles the webhook admission request sent to this webhook.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("Validator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldRT, newRT, err := objectsv3.RoleTemplateOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get RoleTemplate from request: %w", err)
	}

	fldPath := field.NewPath("roletemplate")
	var fieldErr *field.Error

	switch request.Operation {
	case admissionv1.Update:
		if newRT.DeletionTimestamp != nil {
			// Object is in the process of being deleted, so admit it.
			// This admits update operations that happen to remove finalizers.
			// This is needed to supported the deletion of old RoleTemplates that would not pass the update check that verifies all rules have verbs.
			return admission.ResponseAllowed(), nil
		}
		fieldErr = a.validateUpdateFields(oldRT, newRT, fldPath)
	case admissionv1.Create:
		fieldErr = validateCreateFields(newRT, fldPath)
	case admissionv1.Delete:
		return a.validateDelete(oldRT)
	default:
		return nil, fmt.Errorf("roleTemplate operation %v: %w", request.Operation, admission.ErrUnsupportedOperation)
	}
	if fieldErr != nil {
		return admission.ResponseBadRequest(fieldErr.Error()), nil
	}

	// check for circular references produced by this role.
	circularTemplate, err := a.checkCircularRef(newRT)
	if err != nil {
		logrus.Errorf("Error when trying to check for a circular ref: %s", err)
		return nil, err
	}
	if circularTemplate != nil {
		return admission.ResponseBadRequest(fmt.Sprintf("Circular Reference: RoleTemplate %s already inherits RoleTemplate %s", circularTemplate.Name, newRT.Name)), nil
	}

	rules, err := a.roleTemplateResolver.RulesFromTemplate(newRT)
	if err != nil {
		return nil, fmt.Errorf("failed to get all rules for '%s': %w", newRT.Name, err)
	}

	// Verify template rules as per kubernetes rbac rules. Note that we're
	// validating according to the non-namespaced rules to allow .rules
	// including nonResourceURLs.
	if err := common.ValidateRules(rules, false, fldPath.Child("rules")); err != nil {
		return admission.ResponseBadRequest(err.Error()), nil
	}

	allowed, err := auth.RequestUserHasVerb(request, gvr, a.sar, escalateVerb, "", "")
	if err != nil {
		logrus.Warnf("Failed to check for the 'escalate' verb on RoleTemplates: %v", err)
	} else if allowed {
		return admission.ResponseAllowed(), nil
	}

	err = auth.ConfirmNoEscalation(request, rules, "", a.resolver)
	if err != nil {
		return admission.ResponseFailedEscalation(err.Error()), nil
	}

	return admission.ResponseAllowed(), nil
}

// validateUpdateFields checks if the fields being changed are valid update fields.
func (a *admitter) validateUpdateFields(oldRole, newRole *v3.RoleTemplate, fldPath *field.Path) *field.Error {
	if err := validateContextValue(newRole, fldPath); err != nil {
		return err
	}

	// if this is not a built in role, prevent it from becoming one. Otherwise, no further validation is needed
	if !oldRole.Builtin {
		if newRole.Builtin {
			return field.Forbidden(fldPath, fmt.Sprintf("cannot update non-builtIn RoleTemplate %s to be builtIn", oldRole.Name))
		}
		return nil
	}

	// allow changes to meta data and defaults
	oldRole.ClusterCreatorDefault = newRole.ClusterCreatorDefault
	oldRole.ProjectCreatorDefault = newRole.ProjectCreatorDefault
	oldRole.Locked = newRole.Locked

	// we do not want to block K8s controllers from adding metadata or typemeta to the object.
	oldRole.ObjectMeta = newRole.ObjectMeta
	oldRole.TypeMeta = newRole.TypeMeta

	if !equality.Semantic.DeepEqual(oldRole, newRole) {
		return field.Forbidden(fldPath, "updates to builtIn RoleTemplates for fields other than CreatorDefault are forbidden")
	}
	return nil
}

// validateCreateFields checks if all required fields are present and valid.
func validateCreateFields(newRole *v3.RoleTemplate, fldPath *field.Path) *field.Error {
	if newRole.Builtin {
		return field.Forbidden(fldPath, "creating new builtIn RoleTemplates is forbidden")
	}
	return validateContextValue(newRole, fldPath)
}

func validateContextValue(newRole *v3.RoleTemplate, fldPath *field.Path) *field.Error {
	if newRole.Administrative && newRole.Context != clusterContext {
		return field.Forbidden(fldPath.Child("administrative"), "only cluster roles can be administrative")
	}
	if newRole.Context != clusterContext && newRole.Context != projectContext && newRole.Context != emptyContext {
		return field.NotSupported(fldPath.Child("context"), newRole.Context, []string{clusterContext, projectContext})
	}
	return nil
}

func (a *admitter) validateDelete(oldRT *v3.RoleTemplate) (*admissionv1.AdmissionResponse, error) {
	refRT, err := a.roleTemplateResolver.RoleTemplateCache().GetByIndex(rtRefIndex, oldRT.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to list RoleTemplates that reference '%s': %w", oldRT.Name, err)
	}

	// verify that the role is not currently inherited
	if len(refRT) != 0 {
		var names []string
		for _, rt := range refRT {
			names = append(names, rt.Name)
		}
		joinedNames := strings.Join(names, ", ")
		return admission.ResponseBadRequest(fmt.Sprintf("roletemplate %q cannot be deleted because it is inherited by roletemplate(s) %q", oldRT.Name, joinedNames)), nil
	}
	globalRefs, err := a.grCache.GetByIndex(rtGlobalRefIndex, oldRT.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to list GlobalRoles that reference %q: %w", oldRT.Name, err)
	}
	if len(globalRefs) != 0 {
		var names []string
		for _, globalRef := range globalRefs {
			names = append(names, globalRef.Name)
		}
		joinedNames := strings.Join(names, ", ")
		return admission.ResponseBadRequest(fmt.Sprintf("roletemplate %q cannot be deleted because it is inherited by globalRole(s) %q", oldRT.Name, joinedNames)), nil
	}

	return admission.ResponseAllowed(), nil
}

// roleTemplatesByReference returns a list of keys that can be used to retrieve the provided RT.
// each key represents the name of a RoleTemplate that the provided object references.
func roleTemplatesByReference(rt *v3.RoleTemplate) ([]string, error) {
	return rt.RoleTemplateNames, nil
}

func roleTemplatesByGlobalReference(gr *v3.GlobalRole) ([]string, error) {
	return gr.InheritedClusterRoles, nil
}

// checkCircularRef looks for a circular ref between this role template and any role template that it inherits
// for example - template 1 inherits template 2 which inherits template 1. These setups can cause high cpu usage/crashes
// If a circular ref was found, returns the first template which inherits this role template. Returns nil otherwise.
// Can return an error if any role template was not found.
func (a *admitter) checkCircularRef(template *v3.RoleTemplate) (*v3.RoleTemplate, error) {
	seen := make(map[string]struct{})
	queue := []*v3.RoleTemplate{template}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, inherited := range current.RoleTemplateNames {
			// if we found a circular reference, exit here and go no further
			if inherited == template.Name {
				// note: we only look for circular references to this role. We don't check for circular dependencies which
				// don't have this role as one of the targets. Those should have been taken care of when they were originally made
				return current, nil
			}
			// if we haven't seen this yet, we add to the queue to process
			if _, ok := seen[inherited]; !ok {
				newTemplate, err := a.roleTemplateResolver.RoleTemplateCache().Get(inherited)
				if err != nil {
					return nil, fmt.Errorf("unable to get roletemplate %s with error %w", inherited, err)
				}
				seen[inherited] = struct{}{}
				queue = append(queue, newTemplate)
			}
		}
	}
	return nil, nil
}
