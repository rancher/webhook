// Package roletemplate is used for validating roletemplate objects.
package roletemplate

import (
	"fmt"
	"net/http"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/trace"
)

var roleTemplateGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "roletemplates",
}

// NewValidator returns a new validator used for validating roleTemplates.
func NewValidator(resolver validation.AuthorizationRuleResolver, roleTemplateResolver *auth.RoleTemplateResolver,
	sar authorizationv1.SubjectAccessReviewInterface) *Validator {
	return &Validator{
		admitter: admitter{
			resolver:             resolver,
			roleTemplateResolver: roleTemplateResolver,
			sar:                  sar,
		},
	}
}

// Validator for validating roleTemplates.
type Validator struct {
	admitter admitter
}

// GVR returns the GroupVersionKind for this CRD.
func (v *Validator) GVR() schema.GroupVersionResource {
	return roleTemplateGVR
}

// Operations returns list of operations handled by this validator.
func (v *Validator) Operations() []admissionregistrationv1.OperationType {
	return []admissionregistrationv1.OperationType{admissionregistrationv1.Update, admissionregistrationv1.Create}
}

// ValidatingWebhook returns the ValidatingWebhook used for this CRD.
func (v *Validator) ValidatingWebhook(clientConfig admissionregistrationv1.WebhookClientConfig) []admissionregistrationv1.ValidatingWebhook {
	return []admissionregistrationv1.ValidatingWebhook{*admission.NewDefaultValidatingWebhook(v, clientConfig, admissionregistrationv1.ClusterScope, v.Operations())}
}

// Admitters returns the admitter objects used to validate RoleTemplates.
func (v *Validator) Admitters() []admission.Admitter {
	return []admission.Admitter{&v.admitter}
}

type admitter struct {
	resolver             validation.AuthorizationRuleResolver
	roleTemplateResolver *auth.RoleTemplateResolver
	sar                  authorizationv1.SubjectAccessReviewInterface
}

// Admit handles the webhook admission request sent to this webhook.
func (a *admitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("Validator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	roleTemplate, err := objectsv3.RoleTemplateFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, err
	}

	// object is in the process of being deleted, so admit it
	// this admits update operations that happen to remove finalizers
	if roleTemplate.DeletionTimestamp != nil {
		return &admissionv1.AdmissionResponse{Allowed: true}, nil
	}
	//check for circular references produced by this role
	circularTemplate, err := a.checkCircularRef(roleTemplate)
	if err != nil {
		logrus.Errorf("Error when trying to check for a circular ref: %s", err)
		return nil, err
	}
	if circularTemplate != nil {
		return &admissionv1.AdmissionResponse{
			Result: &metav1.Status{
				Status:  "Failure",
				Message: fmt.Sprintf("Circular Reference: RoleTemplate %s already inherits RoleTemplate %s", circularTemplate.Name, roleTemplate.Name),
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			},
			Allowed: false,
		}, nil
	}

	rules, err := a.roleTemplateResolver.RulesFromTemplate(roleTemplate)
	if err != nil {
		return nil, err
	}

	// ensure all PolicyRules have at least one verb, otherwise RBAC controllers may encounter issues when creating Roles and ClusterRoles
	for i := range rules {
		if len(rules[i].Verbs) == 0 {
			return &admissionv1.AdmissionResponse{
				Result: &metav1.Status{
					Status:  "Failure",
					Message: "RoleTemplate.Rules: PolicyRules must have at least one verb",
					Reason:  metav1.StatusReasonBadRequest,
					Code:    http.StatusBadRequest,
				},
				Allowed: false,
			}, nil
		}
	}

	allowed, err := auth.EscalationAuthorized(request, roleTemplateGVR, a.sar, "")
	if err != nil {
		logrus.Warnf("Failed to check for the 'escalate' verb on RoleTemplates: %v", err)
	}

	if allowed {
		return &admissionv1.AdmissionResponse{Allowed: true}, nil
	}
	response := &admissionv1.AdmissionResponse{}
	auth.SetEscalationResponse(response, auth.ConfirmNoEscalation(request, rules, "", a.resolver))
	return response, nil
}

// checkCircularRef looks for a circular ref between this role template and any role template that it inherits
// for example - template 1 inherits template 2 which inherits template 1. These setups can cause high cpu usage/crashes
// If a circular ref was found, returns the first template which inherits this role template. Returns nil otherwise.
// Can return an error if any role template was not found.
func (a *admitter) checkCircularRef(template *v3.RoleTemplate) (*v3.RoleTemplate, error) {
	seen := make(map[string]struct{})
	queue := []*v3.RoleTemplate{template}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, inherited := range current.RoleTemplateNames {
			// if we found a circular reference, exit here and go no further
			if inherited == template.Name {
				// note: we only look for circular references to this role. We don't check for circular dependencies which
				// don't have this role as one of the targets. Those should have been taken care of when they were originally made
				return current, nil
			}
			// if we haven't seen this yet, we add to the queue to process
			if _, ok := seen[inherited]; !ok {
				newTemplate, err := a.roleTemplateResolver.RoleTemplateCache().Get(inherited)
				if err != nil {
					return nil, fmt.Errorf("unable to get roletemplate %s with error %w", inherited, err)
				}
				seen[inherited] = struct{}{}
				queue = append(queue, newTemplate)
			}
		}
	}
	return nil, nil
}
