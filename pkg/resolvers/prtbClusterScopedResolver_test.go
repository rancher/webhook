package resolvers

import (
	"context"
	"testing"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
)

func TestPRTBClusterScopedRuleResolver(t *testing.T) {
	t.Parallel()
	const clusterA = "c-cluster-a"
	const clusterB = "c-cluster-b"

	ruleReadPods := rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"pods"},
	}
	ruleWriteNodes := rbacv1.PolicyRule{
		Verbs:     []string{"PUT", "CREATE", "UPDATE"},
		APIGroups: []string{"v1"},
		Resources: []string{"nodes"},
	}
	ruleReadSecrets := rbacv1.PolicyRule{
		Verbs:     []string{"GET"},
		APIGroups: []string{"v1"},
		Resources: []string{"secrets"},
	}

	// project RoleTemplate with project rules and cluster-scoped rules.
	nodesRT := &apisv3.RoleTemplate{
		ObjectMeta:         metav1.ObjectMeta{Name: "cluster-scoped-nodes"},
		Context:            "project",
		Rules:              []rbacv1.PolicyRule{ruleReadPods},
		ClusterScopedRules: []rbacv1.PolicyRule{ruleWriteNodes},
	}
	secretsRT := &apisv3.RoleTemplate{
		ObjectMeta:         metav1.ObjectMeta{Name: "cluster-scoped-secrets"},
		Context:            "project",
		ClusterScopedRules: []rbacv1.PolicyRule{ruleReadSecrets},
	}
	// project RoleTemplate with only project rules.
	projectOnlyRT := &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "project-only"},
		Context:    "project",
		Rules:      []rbacv1.PolicyRule{ruleWriteNodes, ruleReadSecrets},
	}

	newPRTB := func(name, projectName, userName, groupName, roleTemplateName string) *apisv3.ProjectRoleTemplateBinding {
		return &apisv3.ProjectRoleTemplateBinding{
			ObjectMeta:       metav1.ObjectMeta{Name: name},
			ProjectName:      projectName,
			UserName:         userName,
			GroupName:        groupName,
			RoleTemplateName: roleTemplateName,
		}
	}
	deletingPRTB := newPRTB("deleting", clusterA+":p-one", "user-deleting", "", secretsRT.Name)
	deletingPRTB.DeletionTimestamp = &metav1.Time{}

	bindings := []*apisv3.ProjectRoleTemplateBinding{
		// user1 has PRTBs in two projects of cluster A and one in cluster B.
		newPRTB("user1-nodes-a1", clusterA+":p-one", "user1", "", nodesRT.Name),
		newPRTB("user1-secrets-a2", clusterA+":p-two", "user1", "", secretsRT.Name),
		newPRTB("user1-secrets-b", clusterB+":p-three", "user1", "", secretsRT.Name),
		// user2 only has project rules.
		newPRTB("user2-project-only", clusterA+":p-one", "user2", "", projectOnlyRT.Name),
		// group binding.
		newPRTB("group-nodes", clusterA+":p-two", "", adminGroup, nodesRT.Name),
		// binding whose project name cannot be parsed is not indexed.
		newPRTB("malformed", "p-no-cluster", "user-malformed", "", nodesRT.Name),
		// binding being deleted is not counted.
		deletingPRTB,
		// binding to a missing RoleTemplate returns an error.
		newPRTB("invalid", clusterA+":p-one", "user-invalid", "", invalidName),
		// user principal only: Rancher has not yet set UserName, so it is not indexed.
		{
			ObjectMeta:        metav1.ObjectMeta{Name: "principal-only"},
			ProjectName:       clusterA + ":p-one",
			UserPrincipalName: "github_user://principal-only",
			RoleTemplateName:  nodesRT.Name,
		},
		// both a user name and a user principal: UserName is the subject that is granted permissions.
		{
			ObjectMeta:        metav1.ObjectMeta{Name: "name-and-principal"},
			ProjectName:       clusterA + ":p-one",
			UserName:          "user-name-and-principal",
			UserPrincipalName: "github_user://principal-owner",
			RoleTemplateName:  secretsRT.Name,
		},
		// group principal subject.
		{
			ObjectMeta:         metav1.ObjectMeta{Name: "group-principal"},
			ProjectName:        clusterA + ":p-one",
			GroupPrincipalName: "github_team://team",
			RoleTemplateName:   secretsRT.Name,
		},
	}

	ctrl := gomock.NewController(t)
	roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
	for _, rt := range []*apisv3.RoleTemplate{nodesRT, secretsRT, projectOnlyRT} {
		roleTemplateCache.EXPECT().Get(rt.Name).Return(rt, nil).AnyTimes()
	}
	roleTemplateCache.EXPECT().Get(invalidName).Return(nil, errNotFound).AnyTimes()
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl))
	resolver := NewPRTBClusterScopedRuleResolver(newPRTBClusterCache(ctrl, bindings), roleResolver)

	tests := []struct {
		name        string
		user        user.Info
		clusterName string
		wantRules   Rules
		wantErr     bool
	}{
		{
			name:        "cluster-scoped rules from PRTBs in every project of the cluster, without project rules",
			user:        NewUserInfo("user1"),
			clusterName: clusterA,
			wantRules:   Rules{ruleWriteNodes, ruleReadSecrets},
		},
		{
			name:        "PRTBs in other clusters are not counted",
			user:        NewUserInfo("user1"),
			clusterName: clusterB,
			wantRules:   Rules{ruleReadSecrets},
		},
		{
			name:        "project rules of PRTBs are not counted",
			user:        NewUserInfo("user2"),
			clusterName: clusterA,
			wantRules:   nil,
		},
		{
			name:        "cluster-scoped rules from group PRTBs",
			user:        NewUserInfo("user-without-bindings", adminGroup),
			clusterName: clusterA,
			wantRules:   Rules{ruleWriteNodes},
		},
		{
			name:        "PRTBs with an unparsable project name are not counted",
			user:        NewUserInfo("user-malformed"),
			clusterName: "p-no-cluster",
			wantRules:   nil,
		},
		{
			name:        "PRTBs being deleted are not counted",
			user:        NewUserInfo("user-deleting"),
			clusterName: clusterA,
			wantRules:   nil,
		},
		{
			name:        "missing RoleTemplate returns an error",
			user:        NewUserInfo("user-invalid"),
			clusterName: clusterA,
			wantRules:   nil,
			wantErr:     true,
		},
		{
			name:        "user principal is not indexed until UserName is set",
			user:        NewUserInfo("github_user://principal-only"),
			clusterName: clusterA,
			wantRules:   nil,
		},
		{
			name:        "binding with a name and a principal is credited to the user name",
			user:        NewUserInfo("user-name-and-principal"),
			clusterName: clusterA,
			wantRules:   Rules{ruleReadSecrets},
		},
		{
			name:        "cluster-scoped rules from group principal PRTBs",
			user:        NewUserInfo("user-in-team", "github_team://team"),
			clusterName: clusterA,
			wantRules:   Rules{ruleReadSecrets},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rules, err := resolver.RulesFor(context.Background(), test.user, test.clusterName)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.True(t, test.wantRules.Equal(rules), "wanted=%+v got=%+v", test.wantRules, rules)
		})
	}
}

func newPRTBClusterCache(ctrl *gomock.Controller, bindings []*apisv3.ProjectRoleTemplateBinding) v3.ProjectRoleTemplateBindingCache {
	prtbCache := fake.NewMockCacheInterface[*apisv3.ProjectRoleTemplateBinding](ctrl)
	prtbCache.EXPECT().AddIndexer(prtbClusterSubjectIndex, gomock.Any())
	prtbCache.EXPECT().GetByIndex(prtbClusterSubjectIndex, gomock.Any()).DoAndReturn(func(_ string, subject string) ([]*apisv3.ProjectRoleTemplateBinding, error) {
		var retList []*apisv3.ProjectRoleTemplateBinding
		for _, binding := range bindings {
			keys, _ := prtbByClusterSubject(binding)
			for _, key := range keys {
				if key == subject {
					retList = append(retList, binding)
					break
				}
			}
		}
		return retList, nil
	}).AnyTimes()
	return prtbCache
}
