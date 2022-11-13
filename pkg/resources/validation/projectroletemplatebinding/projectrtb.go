// Package projectroletemplatebinding is used for validating projectroletemplatebinding admission request.
package projectroletemplatebinding

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resolvers"
	"github.com/rancher/webhook/pkg/resources/validation"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8validation "k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/trace"
)

// NewValidator returns a new validator used for validation PRTB.
func NewValidator(prtb v3.ProjectRoleTemplateBindingCache, crtb v3.ClusterRoleTemplateBindingCache,
	defaultResolver k8validation.AuthorizationRuleResolver, roleTemplateResolver *auth.RoleTemplateResolver) *Validator {
	clusterResolver := resolvers.NewAggregateRuleResolver(defaultResolver, resolvers.NewCRTBRuleResolver(crtb, roleTemplateResolver))
	projectResolver := resolvers.NewAggregateRuleResolver(defaultResolver, resolvers.NewPRTBRuleResolver(prtb, roleTemplateResolver))
	return &Validator{
		clusterResolver:      clusterResolver,
		projectResolver:      projectResolver,
		roleTemplateResolver: roleTemplateResolver,
	}
}

// Validator validates PRTB admission request.
type Validator struct {
	clusterResolver      k8validation.AuthorizationRuleResolver
	projectResolver      k8validation.AuthorizationRuleResolver
	roleTemplateResolver *auth.RoleTemplateResolver
}

// Admit is the entrypoint for the validator. Admit will return an error if it unable to process the request.
// If this function is called without NewValidator(..) calls will panic.
func (v *Validator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("projectRoleTemplateBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	if request.Operation == admissionv1.Update {
		oldPRTB, newPRTB, err := objectsv3.ProjectRoleTemplateBindingOldAndNewFromRequest(&request.AdmissionRequest)
		if err != nil {
			return fmt.Errorf("failed to decode PRTB objects from request: %w", err)
		}

		if err = validateUpdateFields(oldPRTB, newPRTB); err != nil {
			response.Result = &metav1.Status{
				Status:  "Failure",
				Message: err.Error(),
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			}
			return nil
		}
	}

	prtb, err := objectsv3.ProjectRoleTemplateBindingFromRequest(&request.AdmissionRequest)
	if err != nil {
		return fmt.Errorf("failed to decode PRTB object from request: %w", err)
	}

	if request.Operation == admissionv1.Create {
		if err = v.validateCreateFields(prtb); err != nil {
			response.Result = &metav1.Status{
				Status:  "Failure",
				Message: err.Error(),
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			}
			return nil
		}
	}

	clusterNS, projectNS := clusterFromProject(prtb.ProjectName)

	roleTemplate, err := v.roleTemplateResolver.RoleTemplateCache().Get(prtb.RoleTemplateName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			response.Allowed = true
			return nil
		}
		return fmt.Errorf("failed to get referenced roleTemplate '%s' for PRTB: %w", roleTemplate.Name, err)
	}

	rules, err := v.roleTemplateResolver.RulesFromTemplate(roleTemplate)
	if err != nil {
		return fmt.Errorf("failed to get rules from referenced roleTemplate '%s': %w", roleTemplate.Name, err)
	}

	err = auth.ConfirmNoEscalation(request, rules, clusterNS, v.clusterResolver)
	if err == nil {
		response.Allowed = true
		return nil
	}

	auth.SetEscalationResponse(response, auth.ConfirmNoEscalation(request, rules, projectNS, v.projectResolver))

	return nil
}

func clusterFromProject(project string) (string, string) {
	pieces := strings.Split(project, ":")
	if len(pieces) < 2 {
		return "", ""
	}
	return pieces[0], pieces[1]
}

// validUpdateFields checks if the fields being changed are valid update fields.
func validateUpdateFields(oldPRTB, newPRTB *apisv3.ProjectRoleTemplateBinding) error {
	var invalidFieldName string
	switch {
	case oldPRTB.RoleTemplateName != newPRTB.RoleTemplateName:
		invalidFieldName = "referenced roleTemplate"
	case oldPRTB.ProjectName != newPRTB.ProjectName:
		invalidFieldName = "projectName"
	case oldPRTB.UserName != newPRTB.UserName && oldPRTB.UserName != "":
		invalidFieldName = "userName"
	case oldPRTB.UserPrincipalName != newPRTB.UserPrincipalName && oldPRTB.UserPrincipalName != "":
		invalidFieldName = "userPrincipalName"
	case oldPRTB.GroupName != newPRTB.GroupName && oldPRTB.GroupName != "":
		invalidFieldName = "groupName"
	case oldPRTB.GroupPrincipalName != newPRTB.GroupPrincipalName && oldPRTB.GroupPrincipalName != "":
		invalidFieldName = "groupPrincipalName"
	case (newPRTB.GroupName != "" || oldPRTB.GroupPrincipalName != "") && (newPRTB.UserName != "" || oldPRTB.UserPrincipalName != ""):
		invalidFieldName = "both user and group"
	default:
		return nil
	}

	return fmt.Errorf("cannot update %s for clusterRoleTemplateBinding %s: %w", invalidFieldName, oldPRTB.Name, validation.ErrInvalidRequest)
}

// validateCreateFields checks if all required fields are present and valid.
func (v *Validator) validateCreateFields(newPRTB *apisv3.ProjectRoleTemplateBinding) error {
	hasUserTarget := newPRTB.UserName != "" || newPRTB.UserPrincipalName != ""
	hasGroupTarget := newPRTB.GroupName != "" || newPRTB.GroupPrincipalName != ""

	if (hasUserTarget && hasGroupTarget) || (!hasUserTarget && !hasGroupTarget) {
		return fmt.Errorf("binding must target either a user [userId]/[userPrincipalId] OR a group [groupId]/[groupPrincipalId]: %w", validation.ErrInvalidRequest)
	}

	if newPRTB.ProjectName == "" {
		return fmt.Errorf("binding must have field projectName set: %w", validation.ErrInvalidRequest)
	}

	roleTemplate, err := v.roleTemplateResolver.RoleTemplateCache().Get(newPRTB.RoleTemplateName)
	if err != nil {
		return fmt.Errorf("unknown reference roleTemplate '%s': %w", newPRTB.RoleTemplateName, err)
	}

	if roleTemplate.Locked {
		return fmt.Errorf("referenced role '%s' is locked and cannot be assigned: %w", roleTemplate.DisplayName, validation.ErrInvalidRequest)
	}

	return nil
}
