package resolvers

import (
	"fmt"

	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/authentication/user"
)

// CRTBRuleResolver implements the rbacv1.AuthorizationRuleResolver interface.
type CRTBRuleResolver struct {
	ClusterRoleTemplateBindings v3.ClusterRoleTemplateBindingCache
	RoleTemplateResolver        *auth.RoleTemplateResolver
}

// NewCRTBRuleResolver returns a new resolver for resolving rules given through ClusterRoleTemplateBindings.
func NewCRTBRuleResolver(crtbCache v3.ClusterRoleTemplateBindingCache, roleTemplateResolver *auth.RoleTemplateResolver) *CRTBRuleResolver {
	return &CRTBRuleResolver{
		ClusterRoleTemplateBindings: crtbCache,
		RoleTemplateResolver:        roleTemplateResolver,
	}
}

// GetRoleReferenceRules is used to find which roles are granted by a rolebinding/clusterrolebinding. Since we don't
// use these primitives to refer to role templates return empty list.
func (c *CRTBRuleResolver) GetRoleReferenceRules(roleRef rbacv1.RoleRef, namespace string) ([]rbacv1.PolicyRule, error) {
	return []rbacv1.PolicyRule{}, nil
}

// RulesFor returns the list of rules that apply to a given user in a given namespace and error.  If an error is returned, the slice of
// PolicyRules may not be complete, but it contains all retrievable rules.  This is done because policy rules are purely additive and policy determinations
// can be made on the basis of those rules that are found.
func (c *CRTBRuleResolver) RulesFor(user user.Info, namespace string) (rules []rbacv1.PolicyRule, retError error) {
	visitor := &ruleAccumulator{}
	c.VisitRulesFor(user, namespace, visitor.visit)
	return visitor.rules, visitor.getError()
}

// VisitRulesFor invokes visitor() with each rule that applies to a given user in a given namespace, and each error encountered resolving those rules.
// If visitor() returns false, visiting is short-circuited.
func (c *CRTBRuleResolver) VisitRulesFor(user user.Info, namespace string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) {
	crtbs, err := c.ClusterRoleTemplateBindings.List(namespace, labels.Everything())
	if err != nil {
		visitor(nil, nil, err)
	}

	for _, crtb := range crtbs {
		if crtb.UserName != user.GetName() {
			continue
		}
		rtRules, err := c.RoleTemplateResolver.RulesFromTemplateName(crtb.RoleTemplateName)
		if !visitRules(nil, rtRules, err, visitor) {
			return
		}
	}
}
