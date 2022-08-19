package clusterroletemplatebinding

import (
	"fmt"
	"net/http"
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

var clusterRoleTemplateBindingGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "clusterroletemplatebindings",
}

func NewValidator(rt v3.RoleTemplateCache, escalationChecker *auth.EscalationChecker) webhook.Handler {
	return &clusterRoleTemplateBindingValidator{
		escalationChecker: escalationChecker,
		roleTemplates:     rt,
	}
}

type clusterRoleTemplateBindingValidator struct {
	escalationChecker *auth.EscalationChecker
	roleTemplates     v3.RoleTemplateCache
}

func (c *clusterRoleTemplateBindingValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("clusterRoleTemplateBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	// disallow updates to the referenced role template
	if request.Operation == admissionv1.Update {
		oldCRTB, newCRTB, err := objectsv3.ClusterRoleTemplateBindingOldAndNewFromRequest(request)
		if err != nil {
			return fmt.Errorf("failed to get old and new CRTB from request: %w", err)
		}

		if err := validateUpdateFields(oldCRTB, newCRTB); err != nil {
			response.Result = &metav1.Status{
				Status:  "Failure",
				Message: err.Error(),
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			}
			return nil
		}
	}

	crtb, err := objectsv3.ClusterRoleTemplateBindingFromRequest(request)
	if err != nil {
		return err
	}

	if request.Operation == admissionv1.Create {
		if err = c.validateCreateFields(crtb); err != nil {
			response.Result = &metav1.Status{
				Status:  "Failure",
				Message: err.Error(),
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			}
			return nil
		}
	}

	rt, err := c.roleTemplates.Get(crtb.RoleTemplateName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			response.Allowed = true
			return nil
		}
		return err
	}

	rules, err := c.escalationChecker.RulesFromTemplate(rt)
	if err != nil {
		return err
	}

	allowed, err := c.escalationChecker.EscalationAuthorized(response, request, clusterRoleTemplateBindingGVR, crtb.ClusterName)
	if err != nil {
		logrus.Warnf("Failed to check for the 'escalate' verb on ClusterRoleTemplateBinding: %v", err)
	}

	if allowed {
		response.Allowed = true
		return nil
	}

	return c.escalationChecker.ConfirmNoEscalation(response, request, rules, crtb.ClusterName)
}

// validUpdateFields checks if the fields being changed are valid update fields.
func validateUpdateFields(oldCRTB, newCRTB *apisv3.ClusterRoleTemplateBinding) error {
	var invalidFieldName string
	switch {
	case oldCRTB.RoleTemplateName != newCRTB.RoleTemplateName:
		invalidFieldName = "referenced roleTemplate"
	case oldCRTB.ClusterName != newCRTB.ClusterName:
		invalidFieldName = "clusterName"
	case oldCRTB.UserName != newCRTB.UserName && oldCRTB.UserName != "":
		invalidFieldName = "userName"
	case oldCRTB.UserPrincipalName != newCRTB.UserPrincipalName && oldCRTB.UserPrincipalName != "":
		invalidFieldName = "userPrincipalName"
	case oldCRTB.GroupName != newCRTB.GroupName && oldCRTB.GroupName != "":
		invalidFieldName = "groupName"
	case oldCRTB.GroupPrincipalName != newCRTB.GroupPrincipalName && oldCRTB.GroupPrincipalName != "":
		invalidFieldName = "groupPrincipalName"
	case (newCRTB.GroupName != "" || oldCRTB.GroupPrincipalName != "") && (newCRTB.UserName != "" || oldCRTB.UserPrincipalName != ""):
		invalidFieldName = "both user and group"
	default:
		return nil
	}

	return fmt.Errorf("cannot update %s for clusterRoleTemplateBinding %s: %w", invalidFieldName, oldCRTB.Name, validation.ErrInvalidRequest)
}

// validateCreateFields checks if all required fields are present and valid.
func (c *clusterRoleTemplateBindingValidator) validateCreateFields(newCRTB *apisv3.ClusterRoleTemplateBinding) error {
	hasUserTarget := newCRTB.UserName != "" || newCRTB.UserPrincipalName != ""
	hasGroupTarget := newCRTB.GroupName != "" || newCRTB.GroupPrincipalName != ""

	if (hasUserTarget && hasGroupTarget) || (!hasUserTarget && !hasGroupTarget) {
		return fmt.Errorf("binding must target either a user [userId]/[userPrincipalId] OR a group [groupId]/[groupPrincipalId]: %w", validation.ErrInvalidRequest)
	}

	if newCRTB.ClusterName == "" {
		return fmt.Errorf("missing required field 'clusterName': %w", validation.ErrInvalidRequest)
	}

	roleTemplate, err := c.roleTemplates.Get(newCRTB.RoleTemplateName)
	if err != nil {
		return fmt.Errorf("unknown reference roleTemplate '%s': %w", newCRTB.RoleTemplateName, err)
	}

	if roleTemplate.Locked {
		return fmt.Errorf("referenced role '%s' is locked and cannot be assigned: %w", roleTemplate.DisplayName, validation.ErrInvalidRequest)
	}

	return nil
}
