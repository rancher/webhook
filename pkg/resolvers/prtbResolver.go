package resolvers

import (
	"fmt"
	"strings"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	prtbSubjectIndex = "management.cattle.io/prtb-by-subject"
)

// PRTBRuleResolver implements the validation.AuthorizationRuleResolver interface.
type PRTBRuleResolver struct {
	ProjectRoleTemplateBindings v3.ProjectRoleTemplateBindingCache
	RoleTemplateResolver        *auth.RoleTemplateResolver
}

// NewPRTBRuleResolver will create a new PRTBRuleResolver.
// This function can only be called once for each unique instance of prtbCache.
func NewPRTBRuleResolver(prtbCache v3.ProjectRoleTemplateBindingCache, roleTemplateResolver *auth.RoleTemplateResolver) *PRTBRuleResolver {
	prtbCache.AddIndexer(prtbSubjectIndex, prtbBySubject)

	return &PRTBRuleResolver{
		ProjectRoleTemplateBindings: prtbCache,
		RoleTemplateResolver:        roleTemplateResolver,
	}
}

// GetRoleReferenceRules is used to find which roles are granted by a rolebinding/clusterrolebinding. Since we don't
// use these primitives to refer to role templates return empty list.
func (p *PRTBRuleResolver) GetRoleReferenceRules(rbacv1.RoleRef, string) ([]rbacv1.PolicyRule, error) {
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
	// for each group check if there are any PRTBs that match subject and namespace using the indexer.
	// For each returned binding get a list of it's rules with the RoleTemplateResolver and call visit for each rule.
	for _, group := range user.GetGroups() {
		prtbs, err := p.ProjectRoleTemplateBindings.GetByIndex(prtbSubjectIndex, GetGroupKey(group, namespace))
		if err != nil {
			visitor(nil, nil, err)
			continue
		}
		for _, prtb := range prtbs {
			rtRules, err := p.RoleTemplateResolver.RulesFromTemplateName(prtb.RoleTemplateName)
			if !visitRules(nil, rtRules, err, visitor) {
				return
			}
		}
	}

	// gather all PRTBs that match this userName and namespace and resolve there rules.
	prtbs, err := p.ProjectRoleTemplateBindings.GetByIndex(prtbSubjectIndex, GetUserKey(user.GetName(), namespace))
	if err != nil {
		visitor(nil, nil, err)
		return
	}
	for _, prtb := range prtbs {
		rtRules, err := p.RoleTemplateResolver.RulesFromTemplateName(prtb.RoleTemplateName)
		if !visitRules(nil, rtRules, err, visitor) {
			return
		}
	}
}

func prtbBySubject(prtb *apisv3.ProjectRoleTemplateBinding) ([]string, error) {
	namespace, ok := namespaceFromProject(prtb.ProjectName)
	if !ok {
		// if we can not determine the namespace from the project name do not index
		return nil, nil
	}
	if prtb.UserName != "" {
		return []string{GetUserKey(prtb.UserName, namespace)}, nil
	}
	if prtb.GroupName != "" {
		return []string{GetGroupKey(prtb.GroupName, namespace)}, nil
	}
	if prtb.GroupPrincipalName != "" {
		return []string{GetGroupKey(prtb.GroupPrincipalName, namespace)}, nil
	}
	return nil, nil
}

// split a project name on ":" if there are not two parts
// then we can not confidently discern which namespace this project belongs too.
func namespaceFromProject(projectName string) (string, bool) {
	// example projectName c-m-csdf:p-sersd
	pieces := strings.Split(projectName, ":")
	if len(pieces) != 2 {
		return "", false
	}
	return pieces[1], true
}
