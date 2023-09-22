// Package clusterroletemplatebinding is used for validating clusterroletemplatebing admission request.
package clusterroletemplatebinding

import (
	"errors"
	"fmt"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resolvers"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	k8validation "k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "clusterroletemplatebindings",
}

const (
	grbOwnerLabel = "authz.management.cattle.io/grb-owner"
)

// NewValidator will create a newly allocated Validator.
func NewValidator(crtb *resolvers.CRTBRuleResolver, defaultResolver k8validation.AuthorizationRuleResolver,
	roleTemplateResolver *auth.RoleTemplateResolver, grbCache v3.GlobalRoleBindingCache, clusterCache v3.ClusterCache) *Validator {
	resolver := resolvers.NewAggregateRuleResolver(defaultResolver, crtb)
	return &Validator{
		admitter: admitter{
			resolver:             resolver,
			roleTemplateResolver: roleTemplateResolver,
			grbCache:             grbCache,
			clusterCache:         clusterCache,
		},
	}
}

// Validator conforms to the webhook.Handler interface and is used for validating request for clusteroletemplatebindings.
type Validator struct {
	admitter admitter
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return gvr
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Update, admissionregistrationv1.Create}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope, v.Operations())}
}

// Admitters returns the admitter objects used to validate clusterRoleTemplateBindings.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
	resolver             k8validation.AuthorizationRuleResolver
	roleTemplateResolver *auth.RoleTemplateResolver
	grbCache             v3.GlobalRoleBindingCache
	clusterCache         v3.ClusterCache
}

// Admit is the entrypoint for the validator. Admit will return an error if it unable to process the request.
// If this function is called without NewValidator(..) calls will panic.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("clusterRoleTemplateBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	fieldPath := field.NewPath("clusterroletemplatebinding")

	if request.Operation == admissionv1.Update {
		oldCRTB, newCRTB, err := objectsv3.ClusterRoleTemplateBindingOldAndNewFromRequest(&request.AdmissionRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to decode old and new CRTB from request: %w", err)
		}

		if err := validateUpdateFields(oldCRTB, newCRTB, fieldPath); err != nil {
			return admission.ResponseBadRequest(err.Error()), nil
		}
	}

	crtb, err := objectsv3.ClusterRoleTemplateBindingFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CRTB from request: %w", err)
	}

	if request.Operation == admissionv1.Create {
		if err = a.validateCreateFields(crtb, fieldPath); err != nil {
			var fieldErr *field.Error
			if errors.As(err, &fieldErr) {
				return admission.ResponseBadRequest(fieldErr.Error()), nil
			}
			return nil, fmt.Errorf("failed to validate fields on create: %w", err)
		}
	}

	roleTemplate, err := a.roleTemplateResolver.RoleTemplateCache().Get(crtb.RoleTemplateName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return &admissionv1.AdmissionResponse{Allowed: true}, nil
		}
		return nil, fmt.Errorf("failed to get roletemplate '%s': %w", crtb.RoleTemplateName, err)
	}

	rules, err := a.roleTemplateResolver.RulesFromTemplate(roleTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve rules from roletemplate '%s': %w", crtb.RoleTemplateName, err)
	}
	response := &admissionv1.AdmissionResponse{}
	auth.SetEscalationResponse(response, auth.ConfirmNoEscalation(request, rules, crtb.ClusterName, a.resolver))

	return response, nil
}

// validUpdateFields checks if the fields being changed are valid update fields.
func validateUpdateFields(oldCRTB, newCRTB *apisv3.ClusterRoleTemplateBinding, fieldPath *field.Path) *field.Error {
	const reason = "field is immutable"
	switch {
	case oldCRTB.RoleTemplateName != newCRTB.RoleTemplateName:
		return field.Invalid(fieldPath.Child("roleTemplateName"), newCRTB.RoleTemplateName, reason)
	case oldCRTB.ClusterName != newCRTB.ClusterName:
		return field.Invalid(fieldPath.Child("clusterName"), newCRTB.ClusterName, reason)
	case oldCRTB.UserName != newCRTB.UserName && oldCRTB.UserName != "":
		return field.Invalid(fieldPath.Child("userName"), newCRTB.UserName, reason)
	case oldCRTB.UserPrincipalName != newCRTB.UserPrincipalName && oldCRTB.UserPrincipalName != "":
		return field.Invalid(fieldPath.Child("userPrincipalName"), newCRTB.UserPrincipalName, reason)
	case oldCRTB.GroupName != newCRTB.GroupName && oldCRTB.GroupName != "":
		return field.Invalid(fieldPath.Child("groupName"), newCRTB.GroupName, reason)
	case oldCRTB.GroupPrincipalName != newCRTB.GroupPrincipalName && oldCRTB.GroupPrincipalName != "":
		return field.Invalid(fieldPath.Child("groupPrincipalName"), newCRTB.GroupPrincipalName, reason)
	case (newCRTB.GroupName != "" || oldCRTB.GroupPrincipalName != "") && (newCRTB.UserName != "" || oldCRTB.UserPrincipalName != ""):
		return field.Forbidden(fieldPath,
			"binding target must target either a user [userName]/[userPrincipalName] OR a group [groupName]/[groupPrincipalName]")
	case (newCRTB.Labels[grbOwnerLabel] != oldCRTB.Labels[grbOwnerLabel]):
		return field.Forbidden(fieldPath.Child("labels"), fmt.Sprintf("label %s is immutable after creation", grbOwnerLabel))
	default:
		return nil
	}
}

// validateCreateFields checks if all required fields are present and valid.
func (a *admitter) validateCreateFields(newCRTB *apisv3.ClusterRoleTemplateBinding, fieldPath *field.Path) error {
	const reason = "field is required"

	hasUserTarget := newCRTB.UserName != "" || newCRTB.UserPrincipalName != ""
	hasGroupTarget := newCRTB.GroupName != "" || newCRTB.GroupPrincipalName != ""

	if (hasUserTarget && hasGroupTarget) || (!hasUserTarget && !hasGroupTarget) {
		return field.Forbidden(fieldPath, "binding must target either a user [userName]/[userPrincipalName] OR a group [groupName]/[groupPrincipalName]")
	}

	if newCRTB.ClusterName == "" {
		return field.Required(fieldPath.Child("clusterName"), reason)
	}

	if newCRTB.ClusterName != newCRTB.Namespace {
		return field.Forbidden(fieldPath, "clusterName and namespace must be the same value")
	}

	cluster, err := a.clusterCache.Get(newCRTB.ClusterName)
	clusterNotFoundErr := field.Invalid(fieldPath.Child("clusterName"), newCRTB.ClusterName, fmt.Sprintf("specified cluster %s not found", newCRTB.ClusterName))
	if err != nil {
		if apierrors.IsNotFound(err) {
			return clusterNotFoundErr
		}
		return fmt.Errorf("unable to verify cluster %s exists: %w", newCRTB.ClusterName, err)
	}
	if cluster == nil {
		return clusterNotFoundErr
	}

	if newCRTB.RoleTemplateName == "" {
		return field.Required(fieldPath.Child("roleTemplateName"), reason)
	}

	roleTemplate, err := a.roleTemplateResolver.RoleTemplateCache().Get(newCRTB.RoleTemplateName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return field.Invalid(fieldPath.Child("roleTemplateName"), newCRTB.RoleTemplateName, "the referenced role template was not found")
		}
		return err
	}

	if roleTemplate.Locked {
		owningGRB, hasGRBLabel := newCRTB.Labels[grbOwnerLabel]
		// if the grb that owns this role is active then allow this binding to use a locked roleTemplate. This allows
		// grbs which inheritClusterRoles to rollout permissions across new clusters, even on a locked roleTemplate.
		if hasGRBLabel {
			grb, err := a.grbCache.Get(owningGRB)
			// confirm that the owning grb actually exists
			if err != nil {
				if apierrors.IsNotFound(err) {
					reason := fmt.Sprintf("label %s refers to a global role that doesn't exist", owningGRB)
					return field.Invalid(fieldPath.Child("labels"), owningGRB, reason)
				}
				return fmt.Errorf("unable to confirm the existence of backing grb %s: %w", owningGRB, err)
			}
			if grb != nil && grb.DeletionTimestamp == nil {
				return nil
			}
		}
		return field.Forbidden(fieldPath.Child("roleTemplate"), fmt.Sprintf("referenced role %s is locked and cannot be assigned", roleTemplate.DisplayName))
	}

	const clusterContext = "cluster"
	if roleTemplate.Context != clusterContext {
		return field.NotSupported(fieldPath.Child("roleTemplate", "context"), roleTemplate.Context, []string{clusterContext})
	}

	return nil
}
