// Package clusterroletemplatebinding is used for validating clusterroletemplatebing admission request.
package clusterroletemplatebinding

import (
	"fmt"
	"net/http"
	"unicode/utf8"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resolvers"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8validation "k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "clusterroletemplatebindings",
}

// NewValidator will create a newly allocated Validator.
func NewValidator(crtb *resolvers.CRTBRuleResolver, defaultResolver k8validation.AuthorizationRuleResolver,
	roleTemplateResolver *auth.RoleTemplateResolver) *Validator {
	resolver := resolvers.NewAggregateRuleResolver(defaultResolver, crtb)
	return &Validator{
		resolver:             resolver,
		roleTemplateResolver: roleTemplateResolver,
	}
}

// Validator conforms to the webhook.Handler interface and is used for validating request for clusteroletemplatebindings.
type Validator struct {
	resolver             k8validation.AuthorizationRuleResolver
	roleTemplateResolver *auth.RoleTemplateResolver
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
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) *admissionregistrationv1.ValidatingWebhook {
	return admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.NamespacedScope)
}

// Admit is the entrypoint for the validator. Admit will return an error if it unable to process the request.
// If this function is called without NewValidator(..) calls will panic.
func (v *Validator) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("clusterRoleTemplateBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	if request.Operation == admissionv1.Update {
		oldCRTB, newCRTB, err := objectsv3.ClusterRoleTemplateBindingOldAndNewFromRequest(&request.AdmissionRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to get old and new CRTB from request: %w", err)
		}

		if err := validateUpdateFields(oldCRTB, newCRTB); err != nil {
			return &admissionv1.AdmissionResponse{
				Result: &metav1.Status{
					Status:  "Failure",
					Message: err.Error(),
					Reason:  metav1.StatusReasonBadRequest,
					Code:    http.StatusBadRequest,
				},
				Allowed: false,
			}, nil
		}
	}

	crtb, err := objectsv3.ClusterRoleTemplateBindingFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get binding crtb from request: %w", err)
	}

	if request.Operation == admissionv1.Create {
		if err = v.validateCreateFields(crtb); err != nil {
			return &admissionv1.AdmissionResponse{
				Result: &metav1.Status{
					Status:  "Failure",
					Message: err.Error(),
					Reason:  metav1.StatusReasonBadRequest,
					Code:    http.StatusBadRequest,
				},
				Allowed: false,
			}, nil
		}
	}

	roleTemplate, err := v.roleTemplateResolver.RoleTemplateCache().Get(crtb.RoleTemplateName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return &admissionv1.AdmissionResponse{Allowed: true}, nil
		}
		return nil, fmt.Errorf("failed to get roletemplate '%s': %w", crtb.RoleTemplateName, err)
	}

	rules, err := v.roleTemplateResolver.RulesFromTemplate(roleTemplate)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve rules from roletemplate '%s': %w", crtb.RoleTemplateName, err)
	}
	response := &admissionv1.AdmissionResponse{}
	auth.SetEscalationResponse(response, auth.ConfirmNoEscalation(request, rules, crtb.ClusterName, v.resolver))

	return response, nil
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

	return fmt.Errorf("cannot update %s for clusterRoleTemplateBinding %s: %w", invalidFieldName, oldCRTB.Name, admission.ErrInvalidRequest)
}

// validateCreateFields checks if all required fields are present and valid.
func (v *Validator) validateCreateFields(newCRTB *apisv3.ClusterRoleTemplateBinding) error {
	if err := validateName(newCRTB); err != nil {
		return err
	}

	hasUserTarget := newCRTB.UserName != "" || newCRTB.UserPrincipalName != ""
	hasGroupTarget := newCRTB.GroupName != "" || newCRTB.GroupPrincipalName != ""

	if (hasUserTarget && hasGroupTarget) || (!hasUserTarget && !hasGroupTarget) {
		return fmt.Errorf("binding must target either a user [userId]/[userPrincipalId] OR a group [groupId]/[groupPrincipalId]: %w", admission.ErrInvalidRequest)
	}

	if newCRTB.ClusterName == "" {
		return fmt.Errorf("missing required field 'clusterName': %w", admission.ErrInvalidRequest)
	}

	roleTemplate, err := v.roleTemplateResolver.RoleTemplateCache().Get(newCRTB.RoleTemplateName)
	if err != nil {
		return fmt.Errorf("unknown reference roleTemplate '%s': %w", newCRTB.RoleTemplateName, err)
	}

	if roleTemplate.Locked {
		return fmt.Errorf("referenced role '%s' is locked and cannot be assigned: %w", roleTemplate.DisplayName, admission.ErrInvalidRequest)
	}

	return nil
}

func validateName(crtb *apisv3.ClusterRoleTemplateBinding) error {
	fullName := fmt.Sprintf("%s_%s", crtb.ClusterName, crtb.Name)
	charLength := utf8.RuneCountInString(fullName)
	if charLength > 63 {
		return fmt.Errorf("combined with cluster name, the binding name is %d characters long, but it can't be longer than 63 characters",
			charLength)
	}
	return nil
}
