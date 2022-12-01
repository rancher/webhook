package resolvers

import (
	"fmt"

	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/authentication/user"
)

// PRTBRuleResolver implements the validation.AuthorizationRuleResolver interface.
type PRTBRuleResolver struct {
	ProjectRoleTemplateBindings v3.ProjectRoleTemplateBindingCache
	RoleTemplateResolver        *auth.RoleTemplateResolver
}

// NewPRTBRuleResolver will create a new PRTBRuleResolver.
func NewPRTBRuleResolver(prtb v3.ProjectRoleTemplateBindingCache, roleTemplateResolver *auth.RoleTemplateResolver) *PRTBRuleResolver {
	return &PRTBRuleResolver{
		ProjectRoleTemplateBindings: prtb,
		RoleTemplateResolver:        roleTemplateResolver,
	}
}

// GetRoleReferenceRules is used to find which roles are granted by a rolebinding/clusterrolebinding. Since we don't
// use these primitives to refer to role templates return empty list.
func (p *PRTBRuleResolver) GetRoleReferenceRules(roleRef rbacv1.RoleRef, namespace string) ([]rbacv1.PolicyRule, error) {
	return []rbacv1.PolicyRule{}, nil
}

// RulesFor returns the list of rules that apply to a given user in a given namespace and error. If an error is returned, the slice of
// PolicyRules may not be complete, but it contains all retrievable rules. This is done because policy rules are purely additive and policy determinations
// can be made on the basis of those rules that are found.
func (p *PRTBRuleResolver) RulesFor(user user.Info, namespace string) ([]rbacv1.PolicyRule, error) {
	visitor := &ruleAccumulator{}
	p.VisitRulesFor(user, namespace, visitor.visit)
	return visitor.rules, visitor.getError()
}

// VisitRulesFor invokes visitor() with each rule that applies to a given user in a given namespace, and each error encountered resolving those rules.
// If visitor() returns false, visiting is short-circuited.
func (p *PRTBRuleResolver) VisitRulesFor(user user.Info, namespace string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) {
	prtbs, err := p.ProjectRoleTemplateBindings.List(namespace, labels.Everything())
	if err != nil {
		visitor(nil, nil, err)
	}

	for _, prtb := range prtbs {
		if prtb.UserName != user.GetName() {
			continue
		}
		rtRules, err := p.RoleTemplateResolver.RulesFromTemplateName(prtb.RoleTemplateName)
		if !visitRules(nil, rtRules, err, visitor) {
			return
		}
	}
}
