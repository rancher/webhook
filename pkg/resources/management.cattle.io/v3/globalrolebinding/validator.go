package globalrolebinding

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resolvers"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
func NewValidator(resolver rbacvalidation.AuthorizationRuleResolver, grbResolver *resolvers.GRBClusterRuleResolver) *Validator {
	return &Validator{
		admitter: admitter{
			resolver:    resolver,
			grbResolver: grbResolver,
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
	grbResolver *resolvers.GRBClusterRuleResolver
}

// Admit handles the webhook admission request sent to this webhook.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("globalRoleBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldGRB, newGRB, err := objectsv3.GlobalRoleBindingOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}
	// if this change only affects metadata, don't validate any further
	// this allows users with the appropriate permissions to manage labels/annotations/finalizers
	if request.Operation == admissionv1.Update && isMetaOnlyChange(oldGRB, newGRB) {
		return admission.ResponseAllowed(), nil
	}
	targetGRB := newGRB
	if request.Operation == admissionv1.Delete {
		targetGRB = oldGRB
	}
	// Pull the global role to get the rules
	globalRole, err := a.grbResolver.GlobalRoleResolver.GlobalRoleCache().Get(targetGRB.GlobalRoleName)
	if err != nil {
		if !errors.IsNotFound(err) {
			return nil, err
		}
		switch request.Operation {
		case admissionv1.Delete: // allow delete operations if the GR is not found
			return &admissionv1.AdmissionResponse{
				Allowed: true,
			}, nil
		case admissionv1.Update: // only allow updates to the finalizers if the GR is not found
			if targetGRB.DeletionTimestamp != nil {
				return &admissionv1.AdmissionResponse{
					Allowed: true,
				}, nil
			}
		}
		// other operations not allowed
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Status:  "Failure",
				Message: fmt.Sprintf("referenced globalRole %s not found, only deletions allowed", targetGRB.Name),
				Reason:  metav1.StatusReasonUnauthorized,
				Code:    http.StatusUnauthorized,
			},
			Allowed: false,
		}, nil
	}
	fieldPath := field.NewPath("globalrolebinding")
	if request.Operation == admissionv1.Create {
		// new bindings can't refer to a locked role template. The GR validator also checks this, but adding the check here
		// allows the GR validator to permit updates to GRs using locked roleTemplates without removing the locked permission
		err := a.validateGlobalRole(globalRole, fieldPath)
		if err != nil {
			if fieldError, ok := err.(*field.Error); ok {
				return admission.ResponseBadRequest(fieldError.Error()), nil
			}
			return nil, err
		}
	}

	clusterRules, err := a.grbResolver.GlobalRoleResolver.ClusterRulesFromRole(globalRole)
	if err != nil {
		if errors.IsNotFound(err) {
			reason := fmt.Sprintf("at least one roleTemplate was not found %s", err.Error())
			return admission.ResponseBadRequest(reason), nil
		}
		return nil, fmt.Errorf("unable to get global rules from role %s: %w", globalRole.Name, err)
	}
	err = auth.ConfirmNoEscalation(request, clusterRules, "", a.grbResolver)
	if err != nil {
		return admission.ResponseFailedEscalation(err.Error()), nil
	}

	rules := a.grbResolver.GlobalRoleResolver.GlobalRulesFromRole(globalRole)
	err = auth.ConfirmNoEscalation(request, rules, "", a.resolver)
	if err != nil {
		return admission.ResponseFailedEscalation(err.Error()), nil
	}
	return admission.ResponseAllowed(), nil
}

// validateGlobalRole validates that the attached global role isn't trying to use a locked RoleTemplate.
func (a *admitter) validateGlobalRole(globalRole *v3.GlobalRole, fieldPath *field.Path) error {
	roleTemplates, err := a.grbResolver.GlobalRoleResolver.GetRoleTemplatesForGlobalRole(globalRole)
	if err != nil {
		if errors.IsNotFound(err) {
			reason := fmt.Sprintf("unable to find all roleTemplates %s", err.Error())
			return field.Invalid(fieldPath, "", reason)
		}
		return fmt.Errorf("unable to get role templates for global role %s: %w", globalRole.Name, err)
	}
	var lockedRTNames []string
	for _, roleTemplate := range roleTemplates {
		if roleTemplate.Locked {
			lockedRTNames = append(lockedRTNames, roleTemplate.Name)
		}
	}
	if len(lockedRTNames) > 0 {
		joinedNames := strings.Join(lockedRTNames, ", ")
		reason := fmt.Sprintf("global role inherits roleTemplate(s) %s which is locked", joinedNames)
		return field.Invalid(fieldPath.Child("globalRoleName"), globalRole.Name, reason)
	}
	return nil
}

// isMetaOnlyChange checks if old and new are deep equal in all fields except metadata. Will return false on a
// non-effectual change
func isMetaOnlyChange(oldGRB *v3.GlobalRoleBinding, newGRB *v3.GlobalRoleBinding) bool {
	oldMeta := oldGRB.ObjectMeta
	newMeta := newGRB.ObjectMeta

	// if the metadata between old/new hasn't changed, then this isn't a metadata only change
	if reflect.DeepEqual(oldMeta, newMeta) {
		// checking equality of global role rules can be very expensive from a cpu perspective
		return false
	}

	oldGRB.ObjectMeta = metav1.ObjectMeta{}
	newGRB.ObjectMeta = metav1.ObjectMeta{}
	result := reflect.DeepEqual(oldGRB, newGRB)
	oldGRB.ObjectMeta = oldMeta
	newGRB.ObjectMeta = newMeta
	return result
}
