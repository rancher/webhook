package resolvers

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

// ClusterWideRuleResolver conforms to the rbac/validation.AuthorizationRuleResolver interface and wraps another resolver
// so that only rules granted cluster-wide are returned. The requested namespace is ignored, which prevents namespaced
// grants (such as RoleBindings) from being counted as cluster-wide permissions.
type ClusterWideRuleResolver struct {
	resolver validation.AuthorizationRuleResolver
}

// NewClusterWideRuleResolver creates a new ClusterWideRuleResolver that only resolves cluster-wide rules from the provided resolver.
func NewClusterWideRuleResolver(resolver validation.AuthorizationRuleResolver) *ClusterWideRuleResolver {
	return &ClusterWideRuleResolver{
		resolver: resolver,
	}
}

// GetRoleReferenceRules calls GetRoleReferenceRules on the wrapped resolver.
func (c *ClusterWideRuleResolver) GetRoleReferenceRules(ctx context.Context, roleRef rbacv1.RoleRef, namespace string) ([]rbacv1.PolicyRule, error) {
	return c.resolver.GetRoleReferenceRules(ctx, roleRef, namespace)
}

// RulesFor returns the list of cluster-wide rules that apply to a given user and error. The namespace is ignored.
// If an error is returned, the slice of PolicyRules may not be complete, but it contains all retrievable rules.
func (c *ClusterWideRuleResolver) RulesFor(ctx context.Context, user user.Info, _ string) ([]rbacv1.PolicyRule, error) {
	return c.resolver.RulesFor(ctx, user, "")
}

// VisitRulesFor invokes VisitRulesFor() on the wrapped resolver for cluster-wide rules only. The namespace is ignored.
func (c *ClusterWideRuleResolver) VisitRulesFor(ctx context.Context, user user.Info, _ string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) {
	c.resolver.VisitRulesFor(ctx, user, "", visitor)
}
