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
	"github.com/rancher/webhook/pkg/resources/validation"
	"github.com/rancher/wrangler/pkg/webhook"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

var projectRoleTemplateBindingGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "projectroletemplatebindings",
}

func NewValidator(rt v3.RoleTemplateCache, escalationChecker *auth.EscalationChecker) webhook.Handler {
	return &projectRoleTemplateBindingValidator{
		escalationChecker: escalationChecker,
		roleTemplates:     rt,
	}
}

type projectRoleTemplateBindingValidator struct {
	escalationChecker *auth.EscalationChecker
	roleTemplates     v3.RoleTemplateCache
}

func (p *projectRoleTemplateBindingValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("projectRoleTemplateBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	// disallow updates to the referenced role template
	if request.Operation == admissionv1.Update {
		oldPRTB, newPRTB, err := objectsv3.ProjectRoleTemplateBindingOldAndNewFromRequest(request)
		if err != nil {
			return err
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

	prtb, err := objectsv3.ProjectRoleTemplateBindingFromRequest(request)
	if err != nil {
		return err
	}

	if request.Operation == admissionv1.Create {
		if err = p.validateCreateFields(prtb); err != nil {
			response.Result = &metav1.Status{
				Status:  "Failure",
				Message: err.Error(),
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			}
			return nil
		}
	}

	_, projectNS := clusterFromProject(prtb.ProjectName)

	rt, err := p.roleTemplates.Get(prtb.RoleTemplateName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			response.Allowed = true
			return nil
		}
		return err
	}

	rules, err := p.escalationChecker.RulesFromTemplate(rt)
	if err != nil {
		return err
	}

	allowed, err := p.escalationChecker.EscalationAuthorized(response, request, projectRoleTemplateBindingGVR, projectNS)
	if err != nil {
		logrus.Warnf("Failed to check for the 'escalate' verb on ProjectRoleTemplateBinding: %v", err)
	}

	if allowed {
		response.Allowed = true
		return nil
	}

	return p.escalationChecker.ConfirmNoEscalation(response, request, rules, projectNS)
}

func clusterFromProject(project string) (string, string) {
	pieces := strings.Split(project, ":")
	return pieces[0], pieces[1]
}

// validUpdateFields checks if the fields being changed are valid update fields.
func validateUpdateFields(oldPRTB, newPRTB *apisv3.ProjectRoleTemplateBinding) error {
	var invalidFieldName string
	switch {
	case oldPRTB.RoleTemplateName != newPRTB.RoleTemplateName:
		invalidFieldName = "referenced roleTemplate"
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
func (p *projectRoleTemplateBindingValidator) validateCreateFields(newPRTB *apisv3.ProjectRoleTemplateBinding) error {
	hasUserTarget := newPRTB.UserName != "" || newPRTB.UserPrincipalName != ""
	hasGroupTarget := newPRTB.GroupName != "" || newPRTB.GroupPrincipalName != ""

	if (hasUserTarget && hasGroupTarget) || (!hasUserTarget && !hasGroupTarget) {
		return fmt.Errorf("binding must target either a user [userId]/[userPrincipalId] OR a group [groupId]/[groupPrincipalId]: %w", validation.ErrInvalidRequest)
	}

	roleTemplate, err := p.roleTemplates.Get(newPRTB.RoleTemplateName)
	if err != nil {
		return fmt.Errorf("unknown reference roleTemplate '%s': %w", newPRTB.RoleTemplateName, err)
	}

	if roleTemplate.Locked {
		return fmt.Errorf("referenced role '%s' is locked and cannot be assigned: %w", roleTemplate.DisplayName, validation.ErrInvalidRequest)
	}

	return nil
}
