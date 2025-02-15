package resolvers

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

// AggregateRuleResolver conforms to the rbac/validation.AuthorizationRuleResolver interface and is used to aggregate multiple other AuthorizationRuleResolver into one resolver.
type AggregateRuleResolver struct {
	resolvers []validation.AuthorizationRuleResolver
}

// NewAggregateRuleResolver creates a new AggregateRuleResolver that will combine the outputs of all resolvers provided.
func NewAggregateRuleResolver(resolvers ...validation.AuthorizationRuleResolver) *AggregateRuleResolver {
	return &AggregateRuleResolver{
		resolvers: resolvers,
	}
}

// GetRoleReferenceRules calls GetRoleReferenceRules on each resolver and returns all returned rules and errors.
func (a *AggregateRuleResolver) GetRoleReferenceRules(ctx context.Context, roleRef rbacv1.RoleRef, namespace string) ([]rbacv1.PolicyRule, error) {
	visitor := &ruleAccumulator{}
	for _, resolver := range a.resolvers {
		rules, err := resolver.GetRoleReferenceRules(ctx, roleRef, namespace)
		visitRules(nil, rules, err, visitor.visit)
	}
	return visitor.rules, visitor.getError()
}

// RulesFor returns the list of rules that apply to a given user in a given namespace and error for all Resolvers. If an error is returned, the slice of
// PolicyRules may not be complete, but it contains all retrievable rules. This is done because policy rules are purely additive and policy determinations
// can be made on the basis of those rules that are found.
func (a *AggregateRuleResolver) RulesFor(ctx context.Context, user user.Info, namespace string) (rules []rbacv1.PolicyRule, retError error) {
	visitor := &ruleAccumulator{}
	a.VisitRulesFor(ctx, user, namespace, visitor.visit)
	return visitor.rules, visitor.getError()
}

// VisitRulesFor invokes VisitRulesFor() on each resolver.
// If visitor() returns false, visiting is short-circuited for that resolver.
func (a *AggregateRuleResolver) VisitRulesFor(ctx context.Context, user user.Info, namespace string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) {
	for _, resolver := range a.resolvers {
		resolver.VisitRulesFor(ctx, user, namespace, visitor)
	}
}
