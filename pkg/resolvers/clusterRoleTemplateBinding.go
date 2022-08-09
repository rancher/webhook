package resolvers

import (
	"fmt"

	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apiserver/pkg/authentication/user"
)

// CRTBResolver implements the rbacv1.AuthorizationRuleResolver interface
type CRTBResolver struct {
	crtbCache  v3.ClusterRoleTemplateBindingCache
	rtCache    v3.RoleTemplateCache
	rtResolver RoleTemplateResolver
}

func (c *CRTBResolver) GetRoleReferenceRules(roleRef rbacv1.RoleRef, namespace string) ([]rbacv1.PolicyRule, error) {
	return nil, nil
}

func (c *CRTBResolver) RulesFor(user user.Info, namespace string) ([]rbacv1.PolicyRule, error) {
	crtbs, err := c.crtbCache.List(namespace, labels.Everything())
	if err != nil {
		return nil, err
	}

	for _, crtb := range crtbs {
		if crtb.UserName == user.GetName() {

		}
	}
	return nil, nil
}

func (c *CRTBResolver) VisitRulesFor(user user.Info, namespace string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) {

}
