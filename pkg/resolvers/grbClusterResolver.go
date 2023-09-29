package resolvers

import (
	"context"
	"fmt"
	"time"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	v1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/serviceaccount"
	"k8s.io/apiserver/pkg/authentication/user"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

const (
	grbSubjectIndex = "management.cattle.io/grb-by-subject"
	localCluster    = "local"
)

var (
	exceptionServiceAccounts = []string{"rancher-backup", "fleet-agent"}
	adminRules               = []rbacv1.PolicyRule{
		{
			APIGroups: []string{rbacv1.APIGroupAll},
			Resources: []string{rbacv1.ResourceAll},
			Verbs:     []string{rbacv1.VerbAll},
		},
		{
			NonResourceURLs: []string{rbacv1.NonResourceAll},
			Verbs:           []string{rbacv1.VerbAll},
		},
	}
)

// GRBClusterRuleResolver implements the rbacv1.AuthorizationRuleResolver interface. Provides rule resolution
// for the permissions a GRB gives that apply in a given cluster (or all clusters).
type GRBClusterRuleResolver struct {
	GlobalRoleBindings v3.GlobalRoleBindingCache
	GlobalRoleResolver *auth.GlobalRoleResolver
	sar                authorizationv1.SubjectAccessReviewInterface
}

// New NewGRBClusterRuleResolver returns a new resolver for resolving rules given through GlobalRoleBindings
// which apply to cluster(s). This function can only be called once for each unique instance of grbCache.
func NewGRBClusterRuleResolver(grbCache v3.GlobalRoleBindingCache, grResolver *auth.GlobalRoleResolver, sar authorizationv1.SubjectAccessReviewInterface) *GRBClusterRuleResolver {
	grbCache.AddIndexer(grbSubjectIndex, grbBySubject)
	return &GRBClusterRuleResolver{
		GlobalRoleBindings: grbCache,
		GlobalRoleResolver: grResolver,
		sar:                sar,
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
	// if we aren't an exception service account, no need to check sa-specific permissions
	if !isExceptionServiceAccount(user) {
		return
	}
	isAdmin, err := g.hasAdminPermissions(user)
	if err != nil {
		visitor(nil, nil, err)
		return
	}
	if isAdmin {
		// exception service accounts are considered to have full permissions for the purposes of the clusterRules
		if !visitRules(nil, adminRules, nil, visitor) {
			return
		}
	}
}

// hasAdminPermissions checks if a given user is an admin
func (g *GRBClusterRuleResolver) hasAdminPermissions(user user.Info) (bool, error) {
	extras := map[string]v1.ExtraValue{}
	for extraKey, extraValue := range user.GetExtra() {
		extras[extraKey] = v1.ExtraValue(extraValue)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	resourceResponse, err := g.sar.Create(ctx, &v1.SubjectAccessReview{
		Spec: v1.SubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Verb:     rbacv1.VerbAll,
				Group:    rbacv1.APIGroupAll,
				Version:  rbacv1.APIGroupAll,
				Resource: rbacv1.ResourceAll,
			},
			User:   user.GetName(),
			Groups: user.GetGroups(),
			UID:    user.GetUID(),
			Extra:  extras,
		}}, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("unable to create sar for user %s: %w", user.GetName(), err)
	}
	if resourceResponse == nil {
		return false, fmt.Errorf("no sar returned from create request for user %s", user.GetName())
	}
	return resourceResponse.Status.Allowed, nil
}

// isExceptionServiceAccount checks if the specified user is one of the rancher service accounts which need to interact
// with globalRoles but don't themselves have grb permissions
func isExceptionServiceAccount(user user.Info) bool {
	isExceptionUser := false
	_, saName, err := serviceaccount.SplitUsername(user.GetName())
	if err != nil {
		// an error indicates that this wasn't a service account, so we can return early
		return false
	}
	for _, exceptionUsername := range exceptionServiceAccounts {
		if saName == exceptionUsername {
			isExceptionUser = true
			break
		}
	}
	if !isExceptionUser {
		return false
	}
	for _, group := range user.GetGroups() {
		if group == serviceaccount.AllServiceAccountsGroup {
			return true
		}
	}
	return false
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
