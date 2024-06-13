package auth

import (
	"fmt"

	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	v1 "github.com/rancher/wrangler/v2/pkg/generated/controllers/rbac/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
)

const ExternalRulesFeature = "external-rules"

// RoleTemplateResolver provides an interface to flatten role templates into slice of rules.
type RoleTemplateResolver struct {
	roleTemplates v3.RoleTemplateCache
	clusterRoles  v1.ClusterRoleCache
	features      v3.FeatureCache
}

// NewRoleTemplateResolver creates a newly allocated RoleTemplateResolver from the provided caches
func NewRoleTemplateResolver(roleTemplates v3.RoleTemplateCache, clusterRoles v1.ClusterRoleCache, features v3.FeatureCache) *RoleTemplateResolver {
	return &RoleTemplateResolver{
		roleTemplates: roleTemplates,
		clusterRoles:  clusterRoles,
		features:      features,
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

// RulesFromTemplate gets all rules from the template and all referenced templates.
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

// gatherRules appends the rules from current template and does a recursive call to get all inherited roles referenced.
func (r *RoleTemplateResolver) gatherRules(roleTemplate *rancherv3.RoleTemplate, rules []rbacv1.PolicyRule, seen map[string]bool) ([]rbacv1.PolicyRule, error) {
	seen[roleTemplate.Name] = true

	if roleTemplate.External {
		externalRulesEnabled, err := r.isExternalRulesFeatureFlagEnabled()
		if err != nil {
			return nil, fmt.Errorf("failed to check externalRules feature flag: %w", err)
		}

		if externalRulesEnabled {
			if roleTemplate.ExternalRules != nil {
				rules = append(rules, roleTemplate.ExternalRules...)
			} else {
				cr, err := r.clusterRoles.Get(roleTemplate.Name)
				if err != nil {
					return nil, fmt.Errorf("for external RoleTemplates, externalRules must be provided or a backing clusterRole must be installed to check for privilege escalations: failed to get ClusterRole %q: %w", roleTemplate.Name, err)
				}
				rules = append(rules, cr.Rules...)
			}
		} else if roleTemplate.Context == "cluster" {
			cr, err := r.clusterRoles.Get(roleTemplate.Name)
			if err != nil {
				return nil, fmt.Errorf("failed to get ClusterRole %q: %w", roleTemplate.Name, err)
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

func (r *RoleTemplateResolver) isExternalRulesFeatureFlagEnabled() (bool, error) {
	f, err := r.features.Get(ExternalRulesFeature)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}
	if f.Spec.Value == nil {
		return f.Status.Default, nil
	}
	return *f.Spec.Value, nil
}
