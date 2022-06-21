package auth

import (
	"context"
	"net/http"

	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	k8srbacv1 "github.com/rancher/wrangler/pkg/generated/controllers/rbac/v1"
	"github.com/rancher/wrangler/pkg/webhook"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/user"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
	rbacregistryvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const (
	CreatorIDAnn = "field.cattle.io/creatorId"
)

// NewEscalationChecker returns a newly allocated EscalationChecker.
func NewEscalationChecker(ruleSolver validation.AuthorizationRuleResolver, roleTemplates v3.RoleTemplateCache, clusterRoles k8srbacv1.ClusterRoleCache,
	sar authorizationv1.SubjectAccessReviewInterface) *EscalationChecker {
	return &EscalationChecker{
		clusterRoles:  clusterRoles,
		roleTemplates: roleTemplates,
		ruleSolver:    ruleSolver,
		sar:           sar,
	}
}

// EscalationChecker struct used for performing privilege escalation checks.
type EscalationChecker struct {
	clusterRoles  k8srbacv1.ClusterRoleCache
	roleTemplates v3.RoleTemplateCache
	ruleSolver    validation.AuthorizationRuleResolver
	sar           authorizationv1.SubjectAccessReviewInterface
}

// ConfirmNoEscalation checks that the user attempting to create a binding/role has all the permissions they are attempting
// to grant.
func (ec *EscalationChecker) ConfirmNoEscalation(response *webhook.Response, request *webhook.Request, rules []rbacv1.PolicyRule, namespace string) error {
	userInfo := &user.DefaultInfo{
		Name:   request.UserInfo.Username,
		UID:    request.UserInfo.UID,
		Groups: request.UserInfo.Groups,
		Extra:  ToExtraString(request.UserInfo.Extra),
	}

	globalCtx := k8srequest.WithNamespace(k8srequest.WithUser(context.Background(), userInfo), namespace)

	if err := rbacregistryvalidation.ConfirmNoEscalation(globalCtx, ec.ruleSolver, rules); err != nil {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: err.Error(),
			Reason:  metav1.StatusReasonInvalid,
			Code:    http.StatusUnprocessableEntity,
		}
		return nil
	}
	response.Allowed = true
	return nil
}

// RulesFromTemplate gets all rules from the template and all referenced templates.
func (ec *EscalationChecker) RulesFromTemplate(rt *rancherv3.RoleTemplate) ([]rbacv1.PolicyRule, error) {
	var rules []rbacv1.PolicyRule
	var err error
	templatesSeen := make(map[string]bool)

	// Kickoff gathering rules
	rules, err = ec.gatherRules(rt, rules, templatesSeen)
	if err != nil {
		return rules, err
	}
	return rules, nil
}

// gatherRules appends the rules from current template and does a recursive call to get all inherited roles referenced.
func (ec *EscalationChecker) gatherRules(rt *rancherv3.RoleTemplate, rules []rbacv1.PolicyRule, seen map[string]bool) ([]rbacv1.PolicyRule, error) {
	seen[rt.Name] = true

	if rt.External && rt.Context == "cluster" {
		cr, err := ec.clusterRoles.Get(rt.Name)
		if err != nil {
			return nil, err
		}
		rules = append(rules, cr.Rules...)
	}

	rules = append(rules, rt.Rules...)

	for _, r := range rt.RoleTemplateNames {
		// If we have already seen the roleTemplate, skip it
		if seen[r] {
			continue
		}
		next, err := ec.roleTemplates.Get(r)
		if err != nil {
			return nil, err
		}
		rules, err = ec.gatherRules(next, rules, seen)
		if err != nil {
			return nil, err
		}
	}
	return rules, nil
}

// ToExtraString will convert a map of  map[string]authenticationv1.ExtraValue to map[string]string.
func ToExtraString(extra map[string]authenticationv1.ExtraValue) map[string][]string {
	result := make(map[string][]string)
	for k, v := range extra {
		result[k] = v
	}
	return result
}

// EscalationAuthorized checks if the user associated with the context is explicitly authorized to escalate the given GVR.
func (ec *EscalationChecker) EscalationAuthorized(response *webhook.Response, request *webhook.Request, gvr schema.GroupVersionResource) (bool, error) {
	extras := map[string]v1.ExtraValue{}
	for k, v := range request.UserInfo.Extra {
		extras[k] = v1.ExtraValue(v)
	}

	resp, err := ec.sar.Create(request.Context, &v1.SubjectAccessReview{
		Spec: v1.SubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Verb:     "escalate",
				Version:  gvr.Version,
				Resource: gvr.Resource,
				Group:    gvr.Group,
			},
			User:   request.UserInfo.Username,
			Groups: request.UserInfo.Groups,
			Extra:  extras,
			UID:    request.UserInfo.UID,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return false, err
	}

	return resp.Status.Allowed, nil
}
