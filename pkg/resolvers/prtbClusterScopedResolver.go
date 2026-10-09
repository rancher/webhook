package resolvers

import (
	"context"
	"fmt"
	"strings"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
)

const (
	prtbClusterSubjectIndex = "management.cattle.io/prtb-by-cluster-subject"
	// principalIDExtraKey is the user extra in which Rancher passes the requesting user's principal IDs when impersonating.
	principalIDExtraKey = "principalid"
)

// PRTBClusterScopedRuleResolver implements the validation.AuthorizationRuleResolver interface. It resolves the
// ClusterScopedRules granted by a user's ProjectRoleTemplateBindings in any project of a cluster, which Rancher grants
// cluster-wide in that cluster. The namespace passed to it must be the cluster name. The project-scoped rules of those
// bindings are never returned, since they only apply within their project.
type PRTBClusterScopedRuleResolver struct {
	ProjectRoleTemplateBindings v3.ProjectRoleTemplateBindingCache
	RoleTemplateResolver        *auth.RoleTemplateResolver
}

// NewPRTBClusterScopedRuleResolver will create a new PRTBClusterScopedRuleResolver.
// This function can only be called once for each unique instance of prtbCache.
func NewPRTBClusterScopedRuleResolver(prtbCache v3.ProjectRoleTemplateBindingCache, roleTemplateResolver *auth.RoleTemplateResolver) *PRTBClusterScopedRuleResolver {
	prtbCache.AddIndexer(prtbClusterSubjectIndex, prtbByClusterSubject)

	return &PRTBClusterScopedRuleResolver{
		ProjectRoleTemplateBindings: prtbCache,
		RoleTemplateResolver:        roleTemplateResolver,
	}
}

// GetRoleReferenceRules is used to find which roles are granted by a rolebinding/clusterrolebinding. Since we don't
// use these primitives to refer to role templates return empty list.
func (p *PRTBClusterScopedRuleResolver) GetRoleReferenceRules(context.Context, rbacv1.RoleRef, string) ([]rbacv1.PolicyRule, error) {
	return []rbacv1.PolicyRule{}, nil
}

// RulesFor returns the list of cluster-scoped rules that apply to a given user in a given cluster and error. If an error is returned, the slice of
// PolicyRules may not be complete, but it contains all retrievable rules. This is done because policy rules are purely additive and policy determinations
// can be made on the basis of those rules that are found.
func (p *PRTBClusterScopedRuleResolver) RulesFor(ctx context.Context, user user.Info, clusterName string) ([]rbacv1.PolicyRule, error) {
	visitor := &ruleAccumulator{}
	p.VisitRulesFor(ctx, user, clusterName, visitor.visit)
	return visitor.rules, visitor.getError()
}

// VisitRulesFor invokes visitor() with each cluster-scoped rule that applies to a given user in a given cluster, and each error encountered resolving those rules.
// If visitor() returns false, visiting is short-circuited.
func (p *PRTBClusterScopedRuleResolver) VisitRulesFor(_ context.Context, user user.Info, clusterName string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) {
	principals := user.GetExtra()[principalIDExtraKey]
	keys := make([]string, 0, len(user.GetGroups())+len(principals)+1)
	for _, group := range user.GetGroups() {
		keys = append(keys, GetGroupKey(group, clusterName))
	}
	for _, principal := range principals {
		keys = append(keys, GetPrincipalKey(principal, clusterName))
	}
	keys = append(keys, GetUserKey(user.GetName(), clusterName))

	for _, key := range keys {
		prtbs, err := p.ProjectRoleTemplateBindings.GetByIndex(prtbClusterSubjectIndex, key)
		if err != nil {
			visitor(nil, nil, err)
			continue
		}
		for _, prtb := range prtbs {
			// a binding that is being deleted is having its permissions removed, so don't count them as held.
			if prtb.DeletionTimestamp != nil {
				continue
			}
			rtRules, err := p.RoleTemplateResolver.ClusterScopedRulesFromTemplateName(prtb.RoleTemplateName)
			if !visitRules(nil, rtRules, err, visitor) {
				return
			}
		}
	}
}

// prtbByClusterSubject indexes a PRTB by its cluster and the subject it actually grants permissions to, using the same
// precedence as the binding's effective subject: UserPrincipalName, UserName, GroupPrincipalName, GroupName, ServiceAccount.
// Only that one subject is indexed, so a binding with both a name and a principal is never credited to the wrong subject.
func prtbByClusterSubject(prtb *apisv3.ProjectRoleTemplateBinding) ([]string, error) {
	clusterName, ok := clusterFromProject(prtb.ProjectName)
	if !ok {
		// if we can not determine the cluster from the project name do not index
		return nil, nil
	}
	switch {
	case prtb.UserPrincipalName != "":
		return []string{GetPrincipalKey(prtb.UserPrincipalName, clusterName)}, nil
	case prtb.UserName != "":
		return []string{GetUserKey(prtb.UserName, clusterName)}, nil
	case prtb.GroupPrincipalName != "":
		return []string{GetGroupKey(prtb.GroupPrincipalName, clusterName)}, nil
	case prtb.GroupName != "":
		return []string{GetGroupKey(prtb.GroupName, clusterName)}, nil
	case prtb.ServiceAccount != "":
		// A service account is an identity within the binding's cluster. Requests to this webhook are made in the local
		// cluster, where a service account with the same namespace and name is a different identity, so only bindings in
		// the local cluster can be matched to the requester.
		if clusterName != localCluster {
			return nil, nil
		}
		namespace, name, ok := strings.Cut(prtb.ServiceAccount, ":")
		if !ok || namespace == "" || name == "" {
			return nil, nil
		}
		return []string{GetUserKey(serviceaccount.MakeUsername(namespace, name), clusterName)}, nil
	default:
		return nil, nil
	}
}

// GetPrincipalKey creates an indexer key based on a user principal ID and cluster name. Principals use their own key
// prefix so they can only be matched against the requester's principal IDs, never their username.
func GetPrincipalKey(principal, clusterName string) string {
	return fmt.Sprintf("principal:%s-%s", principal, clusterName)
}

// clusterFromProject splits a project name on ":" and returns the cluster part. If there are not two parts
// then we can not confidently discern which cluster this project belongs to.
func clusterFromProject(projectName string) (string, bool) {
	// example projectName c-m-csdf:p-sersd
	pieces := strings.Split(projectName, ":")
	if len(pieces) != 2 || pieces[0] == "" {
		return "", false
	}
	return pieces[0], true
}
