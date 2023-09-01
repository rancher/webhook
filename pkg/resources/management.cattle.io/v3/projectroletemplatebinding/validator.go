// Package projectroletemplatebinding is used for validating ProjectRoleTemplateBinding admission requests.
package projectroletemplatebinding

import (
	"errors"
	"fmt"
	"strings"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
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
	Resource: "projectroletemplatebindings",
}

// NewValidator returns a new validator used for validation PRTB.
func NewValidator(prtb *resolvers.PRTBRuleResolver, crtb *resolvers.CRTBRuleResolver,
	defaultResolver k8validation.AuthorizationRuleResolver, roleTemplateResolver *auth.RoleTemplateResolver) *Validator {
	clusterResolver := resolvers.NewAggregateRuleResolver(defaultResolver, crtb)
	projectResolver := resolvers.NewAggregateRuleResolver(defaultResolver, prtb)
	return &Validator{
		admitter: admitter{
			clusterResolver:      clusterResolver,
			projectResolver:      projectResolver,
			roleTemplateResolver: roleTemplateResolver,
		},
	}
}

// Validator validates PRTB admission request.
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

// Admitters returns the admitter objects used to validate ProjectRoleTemplateBindings.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
	clusterResolver      k8validation.AuthorizationRuleResolver
	projectResolver      k8validation.AuthorizationRuleResolver
	roleTemplateResolver *auth.RoleTemplateResolver
}

// Admit is the entrypoint for the validator. Admit will return an error if it's unable to process the request.
// If this method is called on a nil Validator, it panics.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("projectRoleTemplateBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	fieldPath := field.NewPath("projectroletemplatebinding")

	if request.Operation == admissionv1.Update {
		oldPRTB, newPRTB, err := objectsv3.ProjectRoleTemplateBindingOldAndNewFromRequest(&request.AdmissionRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to decode old and new PRTB objects from request: %w", err)
		}
		if err := validateUpdateFields(oldPRTB, newPRTB, fieldPath); err != nil {
			return admission.ResponseBadRequest(err.Error()), nil
		}
	}

	prtb, err := objectsv3.ProjectRoleTemplateBindingFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PRTB object from request: %w", err)
	}

	if request.Operation == admissionv1.Create {
		var fieldErr *field.Error
		if err := a.validateCreateFields(prtb, fieldPath); err != nil {
			if errors.As(err, &fieldErr) {
				return admission.ResponseBadRequest(err.Error()), nil
			}
			return nil, fmt.Errorf("failed to validate fields on create: %w", err)
		}
	}

	clusterNS, projectNS := clusterFromProject(prtb.ProjectName)

	roleTemplate, err := a.roleTemplateResolver.RoleTemplateCache().Get(prtb.RoleTemplateName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return &admissionv1.AdmissionResponse{
				Allowed: true,
			}, nil
		}
		return nil, fmt.Errorf("failed to get referenced roleTemplate '%s' for PRTB: %w", roleTemplate.Name, err)
	}

	rules, err := a.roleTemplateResolver.RulesFromTemplate(roleTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to get rules from referenced roleTemplate '%s': %w", roleTemplate.Name, err)
	}

	err = auth.ConfirmNoEscalation(request, rules, clusterNS, a.clusterResolver)
	if err == nil {
		return &admissionv1.AdmissionResponse{Allowed: true}, nil
	}

	response := &admissionv1.AdmissionResponse{}
	auth.SetEscalationResponse(response, auth.ConfirmNoEscalation(request, rules, projectNS, a.projectResolver))

	return response, nil
}

func clusterFromProject(project string) (string, string) {
	pieces := strings.Split(project, ":")
	if len(pieces) < 2 {
		return "", ""
	}
	return pieces[0], pieces[1]
}

// validUpdateFields checks if the fields being changed are valid update fields.
func validateUpdateFields(oldPRTB, newPRTB *apisv3.ProjectRoleTemplateBinding, fieldPath *field.Path) *field.Error {
	const reason = "field is immutable"
	switch {
	case oldPRTB.RoleTemplateName != newPRTB.RoleTemplateName:
		return field.Invalid(fieldPath.Child("roleTemplateName"), newPRTB.RoleTemplateName, reason)
	case oldPRTB.ProjectName != newPRTB.ProjectName:
		return field.Invalid(fieldPath.Child("projectName"), newPRTB.ProjectName, reason)
	case oldPRTB.UserName != newPRTB.UserName && oldPRTB.UserName != "":
		return field.Invalid(fieldPath.Child("userName"), newPRTB.UserName, reason)
	case oldPRTB.UserPrincipalName != newPRTB.UserPrincipalName && oldPRTB.UserPrincipalName != "":
		return field.Invalid(fieldPath.Child("userPrincipalName"), newPRTB.UserPrincipalName, reason)
	case oldPRTB.GroupName != newPRTB.GroupName && oldPRTB.GroupName != "":
		return field.Invalid(fieldPath.Child("groupName"), newPRTB.GroupName, reason)
	case oldPRTB.GroupPrincipalName != newPRTB.GroupPrincipalName && oldPRTB.GroupPrincipalName != "":
		return field.Invalid(fieldPath.Child("groupPrincipalName"), newPRTB.GroupPrincipalName, reason)
	case (newPRTB.GroupName != "" || oldPRTB.GroupPrincipalName != "") && (newPRTB.UserName != "" || oldPRTB.UserPrincipalName != ""):
		return field.Forbidden(fieldPath,
			"binding must target either a user [userName]/[userPrincipalName] OR a group [groupName]/[groupPrincipalName]")
	case oldPRTB.ServiceAccount != newPRTB.ServiceAccount:
		return field.Forbidden(fieldPath.Child("serviceAccount"), "update is not allowed")
	default:
		return nil
	}
}

// validateCreateFields checks if all required fields are present and valid.
func (a *admitter) validateCreateFields(newPRTB *apisv3.ProjectRoleTemplateBinding, fieldPath *field.Path) error {
	hasUserTarget := newPRTB.UserName != "" || newPRTB.UserPrincipalName != ""
	hasGroupTarget := newPRTB.GroupName != "" || newPRTB.GroupPrincipalName != ""
	hasServiceAccountTarget := newPRTB.ServiceAccount != ""

	if !onlyOneTrue(hasUserTarget, hasGroupTarget, hasServiceAccountTarget) {
		return field.Forbidden(fieldPath,
			"binding must target only a user [userName]/[userPrincipalName] OR a group [groupName]/[groupPrincipalName] OR a [serviceAccount]")
	}

	if newPRTB.ProjectName == "" {
		return field.Required(fieldPath.Child("projectName"), "")
	}

	if newPRTB.RoleTemplateName == "" {
		return field.Required(fieldPath.Child("roleTemplateName"), "")
	}

	roleTemplate, err := a.roleTemplateResolver.RoleTemplateCache().Get(newPRTB.RoleTemplateName)
	if err != nil {
		return err
	}

	if roleTemplate.Locked {
		return field.Forbidden(fieldPath.Child("roleTemplate"), fmt.Sprintf("referenced role '%s' is locked and cannot be assigned", roleTemplate.DisplayName))
	}

	const projectContext = "project"
	if roleTemplate.Context != projectContext {
		return field.NotSupported(fieldPath.Child("roleTemplate", "context"), roleTemplate.Context, []string{projectContext})
	}

	return nil
}

func onlyOneTrue(values ...bool) bool {
	var trueCount int
	for _, v := range values {
		if v {
			trueCount++
		}
	}
	return trueCount == 1
}
