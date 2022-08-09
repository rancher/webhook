package resolvers

import (
	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	v1 "github.com/rancher/wrangler-api/pkg/generated/controllers/rbac/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

type RoleTemplateResolver struct {
	clusterRoles  v1.ClusterRoleCache
	roleTemplates v3.RoleTemplateCache
	seen          map[string][]rbacv1.PolicyRule
}

// RulesFromTemplate gets all rules from the template and all referenced templates.
func (r *RoleTemplateResolver) RulesFromTemplate(rt *rancherv3.RoleTemplate) ([]rbacv1.PolicyRule, error) {
	var rules []rbacv1.PolicyRule
	var err error
	if cachedRules, ok := r.seen[rt.Name]; ok {
		return cachedRules, nil
	}
	templatesSeen := make(map[string]bool)

	// Kickoff gathering rules
	rules, err = r.gatherRules(rt, rules, templatesSeen)
	if err != nil {
		return rules, err
	}
	return rules, nil
}

// gatherRules appends the rules from current template and does a recursive call to get all inherited roles referenced.
func (r *RoleTemplateResolver) gatherRules(rt *rancherv3.RoleTemplate, rules []rbacv1.PolicyRule, seen map[string]bool) ([]rbacv1.PolicyRule, error) {
	seen[rt.Name] = true

	if rt.External && rt.Context == "cluster" {
		cr, err := r.clusterRoles.Get(rt.Name)
		if err != nil {
			return nil, err
		}
		rules = append(rules, cr.Rules...)
	}

	rules = append(rules, rt.Rules...)

	for _, rt := range rt.RoleTemplateNames {
		// If we have already seen the roleTemplate, skip it
		if seen[rt] {
			continue
		}
		next, err := r.roleTemplates.Get(rt)
		if err != nil {
			return nil, err
		}
		rules, err = r.gatherRules(next, rules, seen)
		if err != nil {
			return nil, err
		}
	}
	return rules, nil
}
