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

// GRBClusterRuleResolver implements the rbacv1.AuthorizationRuleResolver interface. Provides rule resolution
// for the permissions a GRB gives that apply in a given cluster (or all clusters).
type GRBClusterRuleResolver struct {
	GlobalRoleBindings v3.GlobalRoleBindingCache
	GlobalRoleResolver *auth.GlobalRoleResolver
}

// New NewGRBClusterRuleResolver returns a new resolver for resolving rules given through GlobalRoleBindings
// which apply to cluster(s). This function can only be called once for each unique instance of grbCache.
func NewGRBClusterRuleResolver(grbCache v3.GlobalRoleBindingCache, grResolver *auth.GlobalRoleResolver) *GRBClusterRuleResolver {
	grbCache.AddIndexer(grbSubjectIndex, grbBySubject)
	return &GRBClusterRuleResolver{
		GlobalRoleBindings: grbCache,
		GlobalRoleResolver: grResolver,
	}
}

// GetRoleReferenceRules is used to find which rules are granted by a rolebinding/clusterRoleBinding. Since we don't
// use these primitives to refer to the globalRoles, this function returns an empty slice.
func (g *GRBClusterRuleResolver) GetRoleReferenceRules(rbacv1.RoleRef, string) ([]rbacv1.PolicyRule, error) {
	return []rbacv1.PolicyRule{}, nil
}

// RulesFor returns the list of Cluster rules that apply in a given namespace (usually either the namespace of a
// specific cluster or "" for all clusters). If an error is returned, the slice of PolicyRules may not be complete,
// but contains all retrievable rules.
func (g *GRBClusterRuleResolver) RulesFor(user user.Info, namespace string) ([]rbacv1.PolicyRule, error) {
	visitor := &ruleAccumulator{}
	g.VisitRulesFor(user, namespace, visitor.visit)
	return visitor.rules, visitor.getError()
}

// VisitRulesFor invokes visitor() with each rule that applies to a given user in a given namespace, and each error encountered resolving those rules.
// If visitor() returns false, visiting is short-circuited. This will return different rules for the "local" namespace.
func (g *GRBClusterRuleResolver) VisitRulesFor(user user.Info, namespace string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) {
	var grbs []*apisv3.GlobalRoleBinding
	// gather all grbs that apply to this user through group or user assignment
	for _, group := range user.GetGroups() {
		groupGrbs, err := g.GlobalRoleBindings.GetByIndex(grbSubjectIndex, GetGroupKey(group, ""))
		if err != nil {
			visitor(nil, nil, err)
			continue
		}
		grbs = append(grbs, groupGrbs...)
	}
	userGrbs, err := g.GlobalRoleBindings.GetByIndex(grbSubjectIndex, GetUserKey(user.GetName(), ""))
	// don't return here - we may have gotten bindings from the group lookup to evaluate
	if err != nil {
		visitor(nil, nil, err)
	} else {
		grbs = append(grbs, userGrbs...)
	}
	for _, grb := range grbs {
		globalRole, err := g.GlobalRoleResolver.GlobalRoleCache().Get(grb.GlobalRoleName)
		if err != nil {
			visitor(nil, nil, err)
			continue
		}
		var rules []rbacv1.PolicyRule
		var ruleError error
		// rules for the local cluster come from the GlobalRoles bucket - the ClusterRules only apply to
		// the downstream clusters, so we take the local cluster rules from the GlobalRules
		if namespace == localCluster {
			rules = g.GlobalRoleResolver.GlobalRulesFromRole(globalRole)
		} else {
			rules, ruleError = g.GlobalRoleResolver.ClusterRulesFromRole(globalRole)
		}
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
