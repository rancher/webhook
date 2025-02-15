package resolvers

import (
	"context"
	"fmt"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	crtbSubjectIndex = "management.cattle.io/crtb-by-subject"
)

// CRTBRuleResolver implements the rbacv1.AuthorizationRuleResolver interface.
type CRTBRuleResolver struct {
	ClusterRoleTemplateBindings v3.ClusterRoleTemplateBindingCache
	RoleTemplateResolver        *auth.RoleTemplateResolver
}

// NewCRTBRuleResolver returns a new resolver for resolving rules given through ClusterRoleTemplateBindings.
// This function can only be called once for each unique instance of crtbCache.
func NewCRTBRuleResolver(crtbCache v3.ClusterRoleTemplateBindingCache, roleTemplateResolver *auth.RoleTemplateResolver) *CRTBRuleResolver {
	crtbCache.AddIndexer(crtbSubjectIndex, crtbBySubject)

	return &CRTBRuleResolver{
		ClusterRoleTemplateBindings: crtbCache,
		RoleTemplateResolver:        roleTemplateResolver,
	}
}

// GetRoleReferenceRules is used to find which roles are granted by a rolebinding/clusterrolebinding. Since we don't
// use these primitives to refer to role templates return empty list.
func (c *CRTBRuleResolver) GetRoleReferenceRules(context.Context, rbacv1.RoleRef, string) ([]rbacv1.PolicyRule, error) {
	return []rbacv1.PolicyRule{}, nil
}

// RulesFor returns the list of rules that apply to a given user in a given namespace and error.  If an error is returned, the slice of
// PolicyRules may not be complete, but it contains all retrievable rules.  This is done because policy rules are purely additive and policy determinations
// can be made on the basis of those rules that are found.
func (c *CRTBRuleResolver) RulesFor(ctx context.Context, user user.Info, namespace string) ([]rbacv1.PolicyRule, error) {
	visitor := &ruleAccumulator{}
	c.VisitRulesFor(ctx, user, namespace, visitor.visit)
	return visitor.rules, visitor.getError()
}

// VisitRulesFor invokes visitor() with each rule that applies to a given user in a given namespace, and each error encountered resolving those rules.
// If visitor() returns false, visiting is short-circuited.
func (c *CRTBRuleResolver) VisitRulesFor(_ context.Context, user user.Info, namespace string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) {
	// for each group check if there are any CRTBs that match subject and namespace using the indexer.
	// For each returned binding get a list of it's rules with the RoleTemplateResolver and call visit for each rule.
	for _, group := range user.GetGroups() {
		crtbs, err := c.ClusterRoleTemplateBindings.GetByIndex(crtbSubjectIndex, GetGroupKey(group, namespace))
		if err != nil {
			visitor(nil, nil, err)
			continue
		}
		for _, crtb := range crtbs {
			rtRules, err := c.RoleTemplateResolver.RulesFromTemplateName(crtb.RoleTemplateName)
			if !visitRules(nil, rtRules, err, visitor) {
				return
			}
		}
	}

	// gather all CRTBs that match this userName and namespace and resolve there rules.
	crtbs, err := c.ClusterRoleTemplateBindings.GetByIndex(crtbSubjectIndex, GetUserKey(user.GetName(), namespace))
	if err != nil {
		visitor(nil, nil, err)
		return
	}
	for _, crtb := range crtbs {
		rtRules, err := c.RoleTemplateResolver.RulesFromTemplateName(crtb.RoleTemplateName)
		if !visitRules(nil, rtRules, err, visitor) {
			return
		}
	}
}

func crtbBySubject(crtb *apisv3.ClusterRoleTemplateBinding) ([]string, error) {
	if crtb.UserName != "" {
		return []string{GetUserKey(crtb.UserName, crtb.ClusterName)}, nil
	}
	if crtb.GroupName != "" {
		return []string{GetGroupKey(crtb.GroupName, crtb.ClusterName)}, nil
	}
	if crtb.GroupPrincipalName != "" {
		return []string{GetGroupKey(crtb.GroupPrincipalName, crtb.ClusterName)}, nil
	}
	return nil, nil
}
