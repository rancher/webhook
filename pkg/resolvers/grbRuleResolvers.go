package resolvers

import (
	"fmt"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	grbSubjectIndex = "management.cattle.io/grb-by-subject"
	localCluster    = "local"
)

// GRBRuleResolvers contains three rule resolvers for: InheritedClusterRules, FleetWorkspaceRules, FleetWorkspaceVerbs.
// InheritedClusterRules grants permissions to all cluster except local.
// FleetWorkspaceRules grants permissions to all fleetworkspaces except local.
// FleetWorkspaceVerbs grants permissions to fleetworkspaces cluster-wide resource except local.
// To ensure that rules are resolved without interference, we require separate resolvers for each of them.
type GRBRuleResolvers struct {
	// ICRResolver resolves rules for GlobalRole rules defined in InheritedClusterRoles.
	ICRResolver *GRBRuleResolver
	// FWRulesResolver resolves rules for GlobalRole rules defined in InheritedFleetWorkspacePermissions.ResourceRules.
	FWRulesResolver *GRBRuleResolver
	// FWVerbsResolver resolves rules for GlobalRole rules defined in InheritedFleetWorkspacePermissions.WorkspaceVerbs.
	FWVerbsResolver *GRBRuleResolver
}

// GRBRuleResolver implements the rbacv1.AuthorizationRuleResolver interface. Provides rule resolution
// for the permissions a GRB gives that apply in a given cluster (or all clusters).
type GRBRuleResolver struct {
	gbrCache     v3.GlobalRoleBindingCache
	grResolver   *auth.GlobalRoleResolver
	ruleResolver func(namespace string, gr *apisv3.GlobalRole, grResolver *auth.GlobalRoleResolver) ([]rbacv1.PolicyRule, error)
}

// NewGRBRuleResolvers returns resolvers for resolving rules given through GlobalRoleBindings
// which apply to cluster(s). This function can only be called once for each unique instance of grbCache.
func NewGRBRuleResolvers(grbCache v3.GlobalRoleBindingCache, grResolver *auth.GlobalRoleResolver) *GRBRuleResolvers {
	grbCache.AddIndexer(grbSubjectIndex, grbBySubject)
	inheritedClusterRoleResolver := &GRBRuleResolver{
		gbrCache:   grbCache,
		grResolver: grResolver,
		ruleResolver: func(namespace string, gr *apisv3.GlobalRole, grResolver *auth.GlobalRoleResolver) ([]rbacv1.PolicyRule, error) {
			var err error
			var rules []rbacv1.PolicyRule
			// the downstream clusters, so we take the local cluster rules from the GlobalRules
			if namespace == localCluster {
				rules = grResolver.GlobalRulesFromRole(gr)
			} else {
				rules, err = grResolver.ClusterRulesFromRole(gr)
			}
			return rules, err
		},
	}
	fleetWorkspaceResourceRulesResolver := &GRBRuleResolver{
		gbrCache:   grbCache,
		grResolver: grResolver,
		ruleResolver: func(_ string, gr *apisv3.GlobalRole, grResolver *auth.GlobalRoleResolver) ([]rbacv1.PolicyRule, error) {
			return grResolver.FleetWorkspacePermissionsResourceRulesFromRole(gr), nil
		},
	}
	fleetWorkspaceVerbsResolver := &GRBRuleResolver{
		gbrCache:   grbCache,
		grResolver: grResolver,
		ruleResolver: func(_ string, gr *apisv3.GlobalRole, grResolver *auth.GlobalRoleResolver) ([]rbacv1.PolicyRule, error) {
			return grResolver.FleetWorkspacePermissionsWorkspaceVerbsFromRole(gr), nil
		},
	}

	return &GRBRuleResolvers{
		ICRResolver:     inheritedClusterRoleResolver,
		FWVerbsResolver: fleetWorkspaceVerbsResolver,
		FWRulesResolver: fleetWorkspaceResourceRulesResolver,
	}
}

// GetRoleReferenceRules is used to find which rules are granted by a rolebinding/clusterRoleBinding. Since we don't
// use these primitives to refer to the globalRoles, this function returns an empty slice.
func (g *GRBRuleResolver) GetRoleReferenceRules(rbacv1.RoleRef, string) ([]rbacv1.PolicyRule, error) {
	return []rbacv1.PolicyRule{}, nil
}

// RulesFor returns the list of Cluster rules that apply in a given namespace (usually either the namespace of a
// specific cluster or "" for all clusters). If an error is returned, the slice of PolicyRules may not be complete,
// but contains all retrievable rules.
func (g *GRBRuleResolver) RulesFor(user user.Info, namespace string) ([]rbacv1.PolicyRule, error) {
	visitor := &ruleAccumulator{}
	g.visitRulesForWithRuleResolver(user, namespace, visitor.visit, g.ruleResolver)
	return visitor.rules, visitor.getError()
}

// VisitRulesFor invokes visitor() with each rule that applies to a given user in a given namespace, and each error encountered resolving those rules.
// If visitor() returns false, visiting is short-circuited. This will return different rules for the "local" namespace.
func (g *GRBRuleResolver) VisitRulesFor(user user.Info, namespace string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) {
	g.visitRulesForWithRuleResolver(user, namespace, visitor, g.ruleResolver)
}

// visitRulesForWithRuleResolver invokes visitor() with each rule that applies to a given user in a given namespace, and each error encountered resolving those rules.
// If visitor() returns false, visiting is short-circuited. This will return different rules for the "local" namespace.
func (g *GRBRuleResolver) visitRulesForWithRuleResolver(user user.Info, namespace string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool, ruleResolver func(namespace string, gr *apisv3.GlobalRole, grResolver *auth.GlobalRoleResolver) ([]rbacv1.PolicyRule, error)) {
	var grbs []*apisv3.GlobalRoleBinding
	// gather all grbs that apply to this user through group or user assignment
	for _, group := range user.GetGroups() {
		groupGrbs, err := g.gbrCache.GetByIndex(grbSubjectIndex, GetGroupKey(group, ""))
		if err != nil {
			visitor(nil, nil, err)
			continue
		}
		grbs = append(grbs, groupGrbs...)
	}
	userGrbs, err := g.gbrCache.GetByIndex(grbSubjectIndex, GetUserKey(user.GetName(), ""))
	// don't return here - we may have gotten bindings from the group lookup to evaluate
	if err != nil {
		visitor(nil, nil, err)
	} else {
		grbs = append(grbs, userGrbs...)
	}
	for _, grb := range grbs {
		globalRole, err := g.grResolver.GlobalRoleCache().Get(grb.GlobalRoleName)
		if err != nil {
			visitor(nil, nil, err)
			continue
		}
		var rules []rbacv1.PolicyRule
		var ruleError error

		rules, ruleError = ruleResolver(namespace, globalRole, g.grResolver)

		if !visitRules(nil, rules, ruleError, visitor) {
			return
		}
	}
}

// grbBySubject indexes a GRB using the subject as the key.
func grbBySubject(grb *apisv3.GlobalRoleBinding) ([]string, error) {
	if grb.UserName != "" {
		return []string{GetUserKey(grb.UserName, "")}, nil
	}
	if grb.GroupPrincipalName != "" {
		return []string{GetGroupKey(grb.GroupPrincipalName, "")}, nil
	}
	return nil, nil
}
