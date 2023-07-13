package globalrolebinding

import (
	"fmt"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/validation/field"
	rbacvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/trace"
)

var gvr = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "globalrolebindings",
}

// NewValidator returns a new validator for GlobalRoleBindings.
func NewValidator(grCache v3.GlobalRoleCache, resolver rbacvalidation.AuthorizationRuleResolver) *Validator {
	return &Validator{
		admitter: admitter{
			resolver:    resolver,
			globalRoles: grCache,
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
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Create, admissionregistrationv1.Update, admissionregistrationv1.Delete}
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
	resolver    rbacvalidation.AuthorizationRuleResolver
	globalRoles v3.GlobalRoleCache
}

// Admit handles the webhook admission request sent to this webhook.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("globalRoleBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldGRB, newGRB, err := objectsv3.GlobalRoleBindingOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to get %s from request: %w", gvr.Resource, err)
	}

	fldPath := field.NewPath(gvr.Resource)
	var fieldErr *field.Error
	switch request.Operation {
	case admissionv1.Update:
		fieldErr = validateUpdateFields(oldGRB, newGRB, fldPath)
	case admissionv1.Create:
		fieldErr = validateCreateFields(newGRB, fldPath)
	case admissionv1.Delete:
		// do nothing
	default:
		return nil, fmt.Errorf("%s operation %v: %w", gvr.Resource, request.Operation, admission.ErrUnsupportedOperation)
	}

	if fieldErr != nil {
		return admission.ResponseBadRequest(fieldErr.Error()), nil
	}

	// Pull the global role to get the rules
	globalRole, err := a.globalRoles.Get(newGRB.GlobalRoleName)
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, fmt.Errorf("failed to get globalrole: %w", err)
		}
		if canSkipEscalation(request.Operation, newGRB) {
			return admission.ResponseAllowed(), nil
		}
		fieldErr := field.NotFound(fldPath.Child("globalRoleName"), newGRB.Name)
		return admission.ResponseBadRequest(fieldErr.Error()), nil
	}

	// if we found the global role perform an escalation check
	if err = auth.ConfirmNoEscalation(request, globalRole.Rules, "", a.resolver); err != nil {
		return admission.ResponseFailedEscalation(err.Error()), nil
	}

	return admission.ResponseAllowed(), nil
}

func canSkipEscalation(op admissionv1.Operation, newGRB *apisv3.GlobalRoleBinding) bool {
	return op == admissionv1.Delete || (op == admissionv1.Update && newGRB.DeletionTimestamp != nil)
}

// validUpdateFields checks if the fields being changed are valid update fields.
func validateUpdateFields(oldBinding, newBinding *apisv3.GlobalRoleBinding, fldPath *field.Path) *field.Error {
	var err *field.Error
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
func validateCreateFields(newBinding *apisv3.GlobalRoleBinding, fldPath *field.Path) *field.Error {
	var err *field.Error
	switch {
	case newBinding.UserName != "" && newBinding.GroupPrincipalName != "":
		err = field.Forbidden(fldPath, "bindings can not set both userName and groupPrincipalName")
	case newBinding.UserName == "" && newBinding.GroupPrincipalName == "":
		err = field.Required(fldPath, "bindings must have either userName or groupPrincipalName set")
	}

	return err
}
