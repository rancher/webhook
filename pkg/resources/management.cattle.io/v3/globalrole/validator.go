package globalrole

import (
	"fmt"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resources/common"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/equality"
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

// NewValidator returns a new validator used for validation globalRoles.
func NewValidator(resolver validation.AuthorizationRuleResolver) *Validator {
	return &Validator{
		admitter: admitter{
			resolver: resolver,
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
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Update, admissionregistrationv1.Create}
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
	resolver validation.AuthorizationRuleResolver
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
	var fieldErr *field.Error

	switch request.Operation {
	case admissionv1.Update:
		if newGR.DeletionTimestamp != nil {
			// Object is in the process of being deleted, so admit it.
			// This admits update operations that happen to remove finalizers.
			// This is needed to supported the deletion of old GlobalRoles that would not pass the update check that verifies all rules have verbs.
			return admission.ResponseAllowed(), nil
		}
		fieldErr = a.validateUpdateFields(oldGR, newGR, fldPath, request)
	case admissionv1.Create:
		fieldErr = validateCreateFields(newGR, fldPath)
	default:
		return nil, fmt.Errorf("globalRole operation %v: %w", request.Operation, admission.ErrUnsupportedOperation)
	}

	if fieldErr != nil {
		return admission.ResponseBadRequest(fieldErr.Error()), nil
	}

	if err = auth.ConfirmNoEscalation(request, newGR.Rules, "", a.resolver); err != nil {
		return admission.ResponseFailedEscalation(err.Error()), nil
	}

	return admission.ResponseAllowed(), nil
}

// validUpdateFields checks if the fields being changed are valid update fields.
func (a *admitter) validateUpdateFields(oldRole, newRole *apisv3.GlobalRole, fldPath *field.Path, request *admission.Request) *field.Error {
	if err := common.CheckForVerbs(newRole.Rules, fldPath); err != nil {
		return field.Required(fldPath.Child("rules"), err.Error())
	}

	if !oldRole.Builtin {
		return nil
	}

	// ignore changes to meta data and newUserDefault
	oldRole.NewUserDefault = newRole.NewUserDefault

	//TODO: Do we want to allow changes to metadata? Norman behavior would drop metaData
	oldRole.ObjectMeta = newRole.ObjectMeta

	if !equality.Semantic.DeepEqual(oldRole, newRole) {
		return field.Forbidden(fldPath, "updates to builtIn GlobalRoles for fields other than 'newUserDefault' are forbidden")
	}
	return nil
}

// validateCreateFields checks if all required fields are present and valid.
func validateCreateFields(newRole *apisv3.GlobalRole, fldPath *field.Path) *field.Error {
	if newRole.DisplayName == "" {
		return field.Required(fldPath.Child("displayName"), "")
	}
	if err := common.CheckForVerbs(newRole.Rules, fldPath); err != nil {
		return field.Required(fldPath.Child("rules"), err.Error())
	}
	return nil
}
