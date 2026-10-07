package resolvers

import (
	"context"
	"fmt"
	"testing"

	"github.com/rancher/webhook/pkg/mocks"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

func TestClusterWideRuleResolver(t *testing.T) {
	t.Parallel()
	const testNamespace = "namespace1"
	testUser := NewUserInfo("testUser")
	ruleWriteNodes := rbacv1.PolicyRule{
		Verbs:     []string{"PUT", "CREATE", "UPDATE"},
		APIGroups: []string{"v1"},
		Resources: []string{"nodes"},
	}
	ruleReadPods := rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"pods"},
	}
	writeNodesCR := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "write-nodes"},
		Rules:      []rbacv1.PolicyRule{ruleWriteNodes},
	}
	readPodsCR := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "read-pods"},
		Rules:      []rbacv1.PolicyRule{ruleReadPods},
	}

	t.Run("namespaced bindings are ignored", func(t *testing.T) {
		t.Parallel()
		roleBindings := []*rbacv1.RoleBinding{
			{
				ObjectMeta: metav1.ObjectMeta{Namespace: testNamespace},
				Subjects:   []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: testUser.GetName()}},
				RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: readPodsCR.Name},
			},
		}
		clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
			{
				Subjects: []rbacv1.Subject{{Kind: rbacv1.UserKind, Name: testUser.GetName()}},
				RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: writeNodesCR.Name},
			},
		}
		defaultResolver, _ := validation.NewTestRuleResolver(nil, roleBindings, []*rbacv1.ClusterRole{writeNodesCR, readPodsCR}, clusterRoleBindings)

		// Sanity check that the default resolver includes the namespaced binding.
		rules, err := defaultResolver.RulesFor(context.Background(), testUser, testNamespace)
		require.NoError(t, err)
		require.ElementsMatch(t, []rbacv1.PolicyRule{ruleWriteNodes, ruleReadPods}, rules)

		resolver := NewClusterWideRuleResolver(defaultResolver)
		rules, err = resolver.RulesFor(context.Background(), testUser, testNamespace)
		require.NoError(t, err)
		require.Equal(t, []rbacv1.PolicyRule{ruleWriteNodes}, rules)

		var visited []rbacv1.PolicyRule
		resolver.VisitRulesFor(context.Background(), testUser, testNamespace, func(_ fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool {
			require.NoError(t, err)
			if rule != nil {
				visited = append(visited, *rule)
			}
			return true
		})
		require.Equal(t, []rbacv1.PolicyRule{ruleWriteNodes}, visited)
	})

	t.Run("wrapped resolver is always called with an empty namespace", func(t *testing.T) {
		t.Parallel()
		mockResolver := mocks.NewMockAuthorizationRuleResolver(gomock.NewController(t))
		mockResolver.EXPECT().RulesFor(gomock.Any(), testUser, "").Return([]rbacv1.PolicyRule{ruleWriteNodes}, nil)
		mockResolver.EXPECT().VisitRulesFor(gomock.Any(), testUser, "", gomock.Any())
		roleRef := rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: "role"}
		mockResolver.EXPECT().GetRoleReferenceRules(gomock.Any(), roleRef, testNamespace).Return([]rbacv1.PolicyRule{ruleReadPods}, nil)

		resolver := NewClusterWideRuleResolver(mockResolver)
		rules, err := resolver.RulesFor(context.Background(), testUser, testNamespace)
		require.NoError(t, err)
		require.Equal(t, []rbacv1.PolicyRule{ruleWriteNodes}, rules)

		resolver.VisitRulesFor(context.Background(), testUser, testNamespace, func(fmt.Stringer, *rbacv1.PolicyRule, error) bool { return true })

		// GetRoleReferenceRules resolves a specific role reference, so its namespace is passed through unchanged.
		rules, err = resolver.GetRoleReferenceRules(context.Background(), roleRef, testNamespace)
		require.NoError(t, err)
		require.Equal(t, []rbacv1.PolicyRule{ruleReadPods}, rules)
	})
}
