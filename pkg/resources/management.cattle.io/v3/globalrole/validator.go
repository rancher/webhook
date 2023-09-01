package globalrole

import (
	"fmt"
	"reflect"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resolvers"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

const roleTemplateClusterContext = "cluster"

// NewValidator returns a new validator used for validation globalRoles.
func NewValidator(ruleResolver validation.AuthorizationRuleResolver, grbResolver *resolvers.GRBClusterRuleResolver) *Validator {
	return &Validator{
		admitter: admitter{
			resolver:    ruleResolver,
			grbResolver: grbResolver,
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
	resolver    validation.AuthorizationRuleResolver
	grbResolver *resolvers.GRBClusterRuleResolver
}

// Admit is the entrypoint for the validator. Admit will return an error if it's unable to process the request.
// If this function is called without NewValidator(..) calls will panic.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("globalRoleValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	oldGR, newGR, err := objectsv3.GlobalRoleOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}
	// object is in the process of being deleted, so admit it
	// this admits update operations that happen to remove finalizers
	if newGR.DeletionTimestamp != nil {
		return admission.ResponseAllowed(), nil
	}

	// if this change only affects metadata, don't validate any further
	// this allows users with the appropriate permissions to manage labels/annotations/finalizers
	if request.Operation == admissionv1.Update && isMetaOnlyChange(oldGR, newGR) {
		return admission.ResponseAllowed(), nil
	}

	err = a.validateInheritedClusterRoles(oldGR, newGR, field.NewPath("globalrole").Child("inheritedClusterRoles"))
	if err != nil {
		if _, ok := err.(*field.Error); ok {
			return admission.ResponseBadRequest(err.Error()), nil
		}
		return nil, err
	}

	// check for escalation separately between cluster permissions and global permissions to prevent crossover
	clusterRules, err := a.grbResolver.GlobalRoleResolver.ClusterRulesFromRole(newGR)
	if err != nil {
		return nil, fmt.Errorf("unable to resolve rules for new global role: %w", err)
	}
	err = auth.ConfirmNoEscalation(request, clusterRules, "", a.grbResolver)
	if err != nil {
		return admission.ResponseFailedEscalation(err.Error()), nil
	}

	// ensure all PolicyRules have at least one verb, otherwise RBAC controllers may encounter issues when creating Roles and ClusterRoles
	for _, rule := range newGR.Rules {
		if len(rule.Verbs) == 0 {
			return admission.ResponseBadRequest("GlobalRole.Rules: PolicyRules must have at least one verb"), nil
		}
	}

	rules := a.grbResolver.GlobalRoleResolver.GlobalRulesFromRole(newGR)

	err = auth.ConfirmNoEscalation(request, rules, "", a.resolver)
	if err != nil {
		return admission.ResponseFailedEscalation(err.Error()), nil
	}

	return admission.ResponseAllowed(), nil
}

// validateInheritedClusterRoles validates that new RoleTemplates specified by InheritedClusterRoles have a context of
// cluster and are not locked. Does NOT check for user privilege escalation. May return a field.Error indicating the
// source of the error.
func (a *admitter) validateInheritedClusterRoles(oldGR *v3.GlobalRole, newGR *v3.GlobalRole, fieldPath *field.Path) error {
	// fetch the old role templates as a map so that we can check which ones from newGR are new
	oldRoleTemplates := map[string]struct{}{}
	if oldGR != nil {
		for _, oldRT := range oldGR.InheritedClusterRoles {
			oldRoleTemplates[oldRT] = struct{}{}
		}
	}

	var currentRoleTemplates []*v3.RoleTemplate
	var err error
	if newGR != nil {
		currentRoleTemplates, err = a.grbResolver.GlobalRoleResolver.GetRoleTemplatesForGlobalRole(newGR)
		if err != nil {
			if apierrors.IsNotFound(err) {
				reason := fmt.Sprintf("unable to find all roleTemplates %s", err.Error())
				return field.Invalid(fieldPath, "", reason)
			}
			return fmt.Errorf("unable to get roleTemplates for current version of GlobalRole %s: %w", oldGR.Name, err)
		}
	}

	var newRoleTemplates []*v3.RoleTemplate
	for _, currentRT := range currentRoleTemplates {
		if _, ok := oldRoleTemplates[currentRT.Name]; !ok {
			newRoleTemplates = append(newRoleTemplates, currentRT)
		}
	}

	// if an RT is locked after the GR is created, we don't want to reject the request. But we also don't want
	// users to add a locked RT as new permissions
	for _, newRT := range newRoleTemplates {
		if newRT.Context != roleTemplateClusterContext {
			reason := fmt.Sprintf("unable to bind a roleTemplate with non-cluster context: %s", newRT.Context)
			return field.Invalid(fieldPath, newRT.Name, reason)
		}
		if newRT.Locked {
			reason := "unable to use locked roleTemplate"
			return field.Invalid(fieldPath, newRT.Name, reason)
		}
	}
	return nil
}

// isMetaOnlyChange checks if old and new are deep equal in all fields except metadata. Will return false on a
// non-effectual change
func isMetaOnlyChange(oldGR *v3.GlobalRole, newGR *v3.GlobalRole) bool {
	oldMeta := oldGR.ObjectMeta
	newMeta := newGR.ObjectMeta

	// if the metadata between old/new hasn't changed, then this isn't a metadata only change
	if reflect.DeepEqual(oldMeta, newMeta) {
		// checking equality of global role rules can be very expensive from a cpu perspective
		return false
	}

	oldGR.ObjectMeta = metav1.ObjectMeta{}
	newGR.ObjectMeta = metav1.ObjectMeta{}
	result := reflect.DeepEqual(oldGR, newGR)
	oldGR.ObjectMeta = oldMeta
	newGR.ObjectMeta = newMeta
	return result
}
