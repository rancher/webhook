package auth

import (
	"context"
	"net/http"

	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	k8srbacv1 "github.com/rancher/webhook/pkg/generated/controllers/rbac.authorization.k8s.io/v1"
	"github.com/rancher/wrangler/pkg/webhook"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
	rbacregistryvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
)

func NewEscalationChecker(ruleSolver validation.AuthorizationRuleResolver, roleTemplates v3.RoleTemplateCache, clusterRoles k8srbacv1.ClusterRoleCache) *EscalationChecker {
	return &EscalationChecker{
		clusterRoles:  clusterRoles,
		roleTemplates: roleTemplates,
		ruleSolver:    ruleSolver,
	}
}

type EscalationChecker struct {
	clusterRoles  k8srbacv1.ClusterRoleCache
	roleTemplates v3.RoleTemplateCache
	ruleSolver    validation.AuthorizationRuleResolver
}

// confirmNoEscalation checks that the user attempting to create a binding/role has all the permissions they are attempting
// to grant
func (ec *EscalationChecker) confirmNoEscalation(response *webhook.Response, request *webhook.Request, rules []rbacv1.PolicyRule, namespace string) error {
	userInfo := &user.DefaultInfo{
		Name:   request.UserInfo.Username,
		UID:    request.UserInfo.UID,
		Groups: request.UserInfo.Groups,
		Extra:  toExtraString(request.UserInfo.Extra),
	}

	globaleCtx := k8srequest.WithNamespace(k8srequest.WithUser(context.Background(), userInfo), namespace)

	if err := rbacregistryvalidation.ConfirmNoEscalation(globaleCtx, ec.ruleSolver, rules); err != nil {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: err.Error(),
			Reason:  metav1.StatusReasonUnauthorized,
			Code:    http.StatusUnauthorized,
		}
		return nil
	}
	response.Allowed = true
	return nil
}

// rulesFromTemplate gets all rules from the template and all referenced templates
func (ec *EscalationChecker) rulesFromTemplate(rt *rancherv3.RoleTemplate) ([]rbacv1.PolicyRule, error) {
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

// gatherRules appends the rules from current template and does a recursive call to get all inherited roles referenced
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
