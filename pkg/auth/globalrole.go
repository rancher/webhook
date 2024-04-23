package auth

import (
	"fmt"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	controllerv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	rbacv1 "k8s.io/api/rbac/v1"
)

// GlobalRoleResolver provides utilities to determine which rules a globalRoles gives in various contexts.
type GlobalRoleResolver struct {
	roleTemplateResolver *RoleTemplateResolver
	globalRoles          controllerv3.GlobalRoleCache
}

const ownerRT = "cluster-owner"

var adminRoles = []string{"restricted-admin"}

// NewRoleTemplateResolver creates a newly allocated RoleTemplateResolver from the provided caches
func NewGlobalRoleResolver(roleTemplateResolver *RoleTemplateResolver, grCache controllerv3.GlobalRoleCache) *GlobalRoleResolver {
	return &GlobalRoleResolver{
		roleTemplateResolver: roleTemplateResolver,
		globalRoles:          grCache,
	}
}

// GlobalRoleCache allows caller to retrieve the globalRoleCache used by the resolver.
func (g *GlobalRoleResolver) GlobalRoleCache() controllerv3.GlobalRoleCache {
	return g.globalRoles
}

// GlobalRulesFromRole finds all rules which apply globally - meaning valid for escalation checks at the cluster scope
// in the local cluster.
func (g *GlobalRoleResolver) GlobalRulesFromRole(gr *v3.GlobalRole) []rbacv1.PolicyRule {
	// no rules on a nil role
	if gr == nil {
		return nil
	}
	return gr.Rules
}

// ClusterRulesFromRole finds all rules which this gr gives on downstream clusters.
func (g *GlobalRoleResolver) ClusterRulesFromRole(gr *v3.GlobalRole) ([]rbacv1.PolicyRule, error) {
	if gr == nil {
		return nil, nil
	}
	// restricted admin is treated like it is owner of all downstream clusters
	// but it doesn't get the same field because this would duplicate legacy logic
	for _, name := range adminRoles {
		if gr.Name == name {
			templateRules, err := g.roleTemplateResolver.RulesFromTemplateName(ownerRT)
			if err != nil {
				return nil, fmt.Errorf("unable to resolve cluster-owner rules: %w", err)
			}
			return templateRules, nil
		}
	}
	var rules []rbacv1.PolicyRule
	for _, inheritedRoleTemplate := range gr.InheritedClusterRoles {
		templateRules, err := g.roleTemplateResolver.RulesFromTemplateName(inheritedRoleTemplate)
		if err != nil {
			return nil, fmt.Errorf("unable to get cluster rules for roleTemplate %s: %w", inheritedRoleTemplate, err)
		}
		rules = append(rules, templateRules...)
	}

	return rules, nil
}

func (g *GlobalRoleResolver) FleetWorkspacePermissionsResourceRulesFromRole(gr *v3.GlobalRole) []rbacv1.PolicyRule {
	if gr == nil {
		return nil
	}

	return gr.InheritedFleetWorkspacePermissions.ResourceRules
}

func (g *GlobalRoleResolver) FleetWorkspacePermissionsWorkspaceVerbsFromRole(gr *v3.GlobalRole) []rbacv1.PolicyRule {
	if gr == nil {
		return nil
	}

	if gr.InheritedFleetWorkspacePermissions.WorkspaceVerbs != nil {
		return []rbacv1.PolicyRule{{
			Verbs:     gr.InheritedFleetWorkspacePermissions.WorkspaceVerbs,
			APIGroups: []string{"management.cattle.io"},
			Resources: []string{"fleetworkspaces"},
		}}
	}

	return nil
}

// GetRoleTemplate allows the caller to retrieve the roleTemplates in use by a given global role. Does not
// recursively evaluate roleTemplates - only returns the top-level resources.
func (g *GlobalRoleResolver) GetRoleTemplatesForGlobalRole(gr *v3.GlobalRole) ([]*v3.RoleTemplate, error) {
	if gr == nil {
		return nil, nil
	}
	var roleTemplates []*v3.RoleTemplate
	for _, inheritedRoleTemplate := range gr.InheritedClusterRoles {
		roleTemplate, err := g.roleTemplateResolver.RoleTemplateCache().Get(inheritedRoleTemplate)
		if err != nil {
			return nil, fmt.Errorf("unable to get roleTemplate %s: %w", inheritedRoleTemplate, err)
		}
		roleTemplates = append(roleTemplates, roleTemplate)
	}
	return roleTemplates, nil
}
