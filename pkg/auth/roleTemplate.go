package auth

import (
	"fmt"

	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	v1 "github.com/rancher/wrangler/v3/pkg/generated/controllers/rbac/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

const projectContext = "project"

// RoleTemplateResolver provides an interface to flatten role templates into slice of rules.
type RoleTemplateResolver struct {
	roleTemplates v3.RoleTemplateCache
	clusterRoles  v1.ClusterRoleCache
}

// NewRoleTemplateResolver creates a newly allocated RoleTemplateResolver from the provided caches
func NewRoleTemplateResolver(roleTemplates v3.RoleTemplateCache, clusterRoles v1.ClusterRoleCache) *RoleTemplateResolver {
	return &RoleTemplateResolver{
		roleTemplates: roleTemplates,
		clusterRoles:  clusterRoles,
	}
}

// RoleTemplateCache allows caller to retrieve the roleTemplateCache used by the resolver.
func (r *RoleTemplateResolver) RoleTemplateCache() v3.RoleTemplateCache { return r.roleTemplates }

// RulesFromTemplateName gets the rules for a roleTemplate with a given name. Simple wrapper around RulesFromTemplate.
func (r *RoleTemplateResolver) RulesFromTemplateName(name string) ([]rbacv1.PolicyRule, error) {
	rt, err := r.roleTemplates.Get(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get RoleTemplate '%s': %w", name, err)
	}
	return r.RulesFromTemplate(rt)
}

// RulesFromTemplate gets all rules from the template and all referenced templates, excluding ClusterScopedRules.
// This is also the full set of rules granted when the template is bound at the cluster level (through a
// ClusterRoleTemplateBinding or a GlobalRole's InheritedClusterRoles): Rancher only aggregates ClusterScopedRules
// into a separate cluster-scoped role for project-context templates, so cluster bindings never grant them.
// Use ClusterScopedRulesFromTemplate to gather the ClusterScopedRules granted by project bindings.
func (r *RoleTemplateResolver) RulesFromTemplate(roleTemplate *rancherv3.RoleTemplate) ([]rbacv1.PolicyRule, error) {
	var rules []rbacv1.PolicyRule
	var err error

	if roleTemplate == nil {
		return rules, nil
	}

	templatesSeen := make(map[string]bool)

	// Kickoff gathering rules
	rules, err = r.gatherRules(roleTemplate, rules, templatesSeen)
	if err != nil {
		return rules, err
	}
	return rules, nil
}

// ClusterScopedRulesFromTemplateName gets the ClusterScopedRules for a roleTemplate with a given name. Simple wrapper around ClusterScopedRulesFromTemplate.
func (r *RoleTemplateResolver) ClusterScopedRulesFromTemplateName(name string) ([]rbacv1.PolicyRule, error) {
	rt, err := r.roleTemplates.Get(name)
	if err != nil {
		return nil, fmt.Errorf("failed to get RoleTemplate '%s': %w", name, err)
	}
	return r.ClusterScopedRulesFromTemplate(rt)
}

// ClusterScopedRulesFromTemplate gets the ClusterScopedRules that a project binding (PRTB) to the template grants
// cluster-wide. Rancher only builds the cluster-scoped role for project-context templates and aggregates the cluster-scoped
// roles of the project-context templates they inherit, so only the template and inherited project-context templates are
// followed; inheritance through any other template is not. This is used both for the rules a binding would grant and for
// the rules a user already holds, so the two stay consistent.
func (r *RoleTemplateResolver) ClusterScopedRulesFromTemplate(roleTemplate *rancherv3.RoleTemplate) ([]rbacv1.PolicyRule, error) {
	var rules []rbacv1.PolicyRule

	if roleTemplate == nil {
		return rules, nil
	}

	templatesSeen := make(map[string]bool)

	return r.gatherClusterScopedRules(roleTemplate, rules, templatesSeen)
}

// gatherRules appends the rules from current template and does a recursive call to get all inherited roles referenced.
func (r *RoleTemplateResolver) gatherRules(roleTemplate *rancherv3.RoleTemplate, rules []rbacv1.PolicyRule, seen map[string]bool) ([]rbacv1.PolicyRule, error) {
	seen[roleTemplate.Name] = true

	if roleTemplate.External {
		if roleTemplate.ExternalRules != nil {
			rules = append(rules, roleTemplate.ExternalRules...)
		} else {
			cr, err := r.clusterRoles.Get(roleTemplate.Name)
			if err != nil {
				return nil, fmt.Errorf("for external RoleTemplates, externalRules must be provided or a backing clusterRole must be installed to check for privilege escalations: failed to get ClusterRole %q: %w", roleTemplate.Name, err)
			}
			rules = append(rules, cr.Rules...)
		}
	}

	rules = append(rules, roleTemplate.Rules...)

	for _, templateName := range roleTemplate.RoleTemplateNames {
		// If we have already seen the roleTemplate, skip it
		if seen[templateName] {
			continue
		}
		next, err := r.roleTemplates.Get(templateName)
		if err != nil {
			return nil, fmt.Errorf("failed to get RoleTemplate '%s': %w", templateName, err)
		}
		rules, err = r.gatherRules(next, rules, seen)
		if err != nil {
			return nil, err
		}
	}
	return rules, nil
}

// gatherClusterScopedRules appends the ClusterScopedRules from the current template and recurses into inherited templates.
// Templates that are not project-context, and the templates they inherit, are skipped since they have no cluster-scoped role.
func (r *RoleTemplateResolver) gatherClusterScopedRules(roleTemplate *rancherv3.RoleTemplate, rules []rbacv1.PolicyRule, seen map[string]bool) ([]rbacv1.PolicyRule, error) {
	seen[roleTemplate.Name] = true

	if roleTemplate.Context != projectContext {
		return rules, nil
	}

	rules = append(rules, roleTemplate.ClusterScopedRules...)

	for _, templateName := range roleTemplate.RoleTemplateNames {
		// If we have already seen the roleTemplate, skip it
		if seen[templateName] {
			continue
		}
		next, err := r.roleTemplates.Get(templateName)
		if err != nil {
			return nil, fmt.Errorf("failed to get RoleTemplate '%s': %w", templateName, err)
		}
		rules, err = r.gatherClusterScopedRules(next, rules, seen)
		if err != nil {
			return nil, err
		}
	}
	return rules, nil
}
