package resolvers

// test generated with:
// mockgen --build_flags=--mod=mod -package resolvers -destination ./mockAuthRuleResolver_test.go "k8s.io/kubernetes/pkg/registry/rbac/validation" AuthorizationRuleResolver
import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/rancher/webhook/pkg/mocks"
	"github.com/stretchr/testify/suite"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

type AggregateResolverSuite struct {
	suite.Suite
	ruleReadPods rbacv1.PolicyRule
	ruleAdmin    rbacv1.PolicyRule
}

func TestAggregateResolver(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(AggregateResolverSuite))
}

func (a *AggregateResolverSuite) SetupSuite() {
	a.ruleReadPods = rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"pods"},
	}
	a.ruleAdmin = rbacv1.PolicyRule{
		Verbs:     []string{"*"},
		APIGroups: []string{"*"},
		Resources: []string{"*"},
	}
}

func (a *AggregateResolverSuite) TestAggregateRuleResolverGetRules() {
	const testNameSpace = "namespace1"
	testUser := NewUserInfo("testUser")

	tests := []struct {
		name      string
		user      user.Info
		namespace string
		resolvers func(*testing.T) ([]validation.AuthorizationRuleResolver, Rules)
		wantRules Rules
		wantErr   bool
	}{
		{
			name:      "rules from single resolver",
			user:      testUser,
			namespace: testNameSpace,
			resolvers: func(t *testing.T) ([]validation.AuthorizationRuleResolver, Rules) {
				expectedRules := []rbacv1.PolicyRule{a.ruleAdmin}
				resolver := mocks.NewMockAuthorizationRuleResolver(gomock.NewController(t))
				resolver.EXPECT().VisitRulesFor(testUser, testNameSpace, gomock.Any()).
					DoAndReturn(func(_ user.Info, _ string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) bool {
						for _, rule := range expectedRules {
							visitor(nil, &rule, nil)
						}
						return true
					})
				resolver.EXPECT().GetRoleReferenceRules(gomock.Any(), gomock.Any()).Return(expectedRules, nil)
				return []validation.AuthorizationRuleResolver{resolver}, expectedRules
			},
		},
		{
			name:      "rules from invalid user",
			user:      NewUserInfo("invalidUser"),
			namespace: testNameSpace,
			wantErr:   true,
			resolvers: func(t *testing.T) ([]validation.AuthorizationRuleResolver, Rules) {
				expectedRules := []rbacv1.PolicyRule{}
				resolver := mocks.NewMockAuthorizationRuleResolver(gomock.NewController(t))
				resolver.EXPECT().VisitRulesFor(gomock.Any(), testNameSpace, gomock.Any()).
					DoAndReturn(func(_ user.Info, _ string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) bool {
						visitor(nil, nil, errNotFound)
						return true
					})
				resolver2 := mocks.NewMockAuthorizationRuleResolver(gomock.NewController(t))
				resolver2.EXPECT().VisitRulesFor(gomock.Any(), testNameSpace, gomock.Any()).
					DoAndReturn(func(_ user.Info, _ string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) bool {
						visitor(nil, nil, errNotFound)
						return true
					})
				return []validation.AuthorizationRuleResolver{resolver, resolver2}, expectedRules
			},
		},
		{
			name:      "rules from second resolver in list",
			user:      testUser,
			namespace: testNameSpace,
			resolvers: func(t *testing.T) ([]validation.AuthorizationRuleResolver, Rules) {
				expectedRules := []rbacv1.PolicyRule{a.ruleReadPods}
				resolver := mocks.NewMockAuthorizationRuleResolver(gomock.NewController(t))
				resolver.EXPECT().VisitRulesFor(testUser, testNameSpace, gomock.Any()).
					DoAndReturn(func(_ user.Info, _ string, _ func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) bool {
						return true
					})
				resolver.EXPECT().GetRoleReferenceRules(gomock.Any(), gomock.Any()).Return(expectedRules, nil)
				resolver2 := mocks.NewMockAuthorizationRuleResolver(gomock.NewController(t))
				resolver2.EXPECT().VisitRulesFor(testUser, testNameSpace, gomock.Any()).
					DoAndReturn(func(_ user.Info, _ string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) bool {
						for _, rule := range expectedRules {
							visitor(nil, &rule, nil)
						}
						return true
					})
				resolver2.EXPECT().GetRoleReferenceRules(gomock.Any(), gomock.Any()).Return(nil, nil)
				return []validation.AuthorizationRuleResolver{resolver, resolver2}, expectedRules
			},
		},
		{
			name:      "rules from both resolvers in list",
			user:      testUser,
			namespace: testNameSpace,
			resolvers: func(t *testing.T) ([]validation.AuthorizationRuleResolver, Rules) {
				expectedRules1 := []rbacv1.PolicyRule{a.ruleAdmin}
				expectedRules2 := []rbacv1.PolicyRule{a.ruleReadPods}
				resolver := mocks.NewMockAuthorizationRuleResolver(gomock.NewController(t))
				resolver.EXPECT().VisitRulesFor(testUser, testNameSpace, gomock.Any()).
					DoAndReturn(func(_ user.Info, _ string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) bool {
						for _, rule := range expectedRules1 {
							visitor(nil, &rule, nil)
						}
						return true
					})
				resolver.EXPECT().GetRoleReferenceRules(gomock.Any(), gomock.Any()).Return(expectedRules1, nil)
				resolver2 := mocks.NewMockAuthorizationRuleResolver(gomock.NewController(t))
				resolver2.EXPECT().VisitRulesFor(testUser, testNameSpace, gomock.Any()).
					DoAndReturn(func(_ user.Info, _ string, visitor func(source fmt.Stringer, rule *rbacv1.PolicyRule, err error) bool) bool {
						for _, rule := range expectedRules2 {
							visitor(nil, &rule, nil)
						}
						return true
					})
				resolver2.EXPECT().GetRoleReferenceRules(gomock.Any(), gomock.Any()).Return(expectedRules2, nil)
				return []validation.AuthorizationRuleResolver{resolver, resolver2}, append(expectedRules1, expectedRules2...)
			},
		},
	}
	for _, tt := range tests {
		a.Run(tt.name, func() {
			resolverList, expectedRules := tt.resolvers(a.T())
			agg := NewAggregateRuleResolver(resolverList...)
			gotRules, err := agg.RulesFor(tt.user, tt.namespace)
			if tt.wantErr {
				a.Errorf(err, "AggregateRuleResolver.RulesFor() error = %v, wantErr %v", err, tt.wantErr)
				// still check result because function is suppose to return partial results.

				if !expectedRules.Equal(gotRules) {
					a.Fail("List of rules did not match", "wanted=%+v got=%+v", expectedRules, gotRules)
				}
				return
			}
			a.NoError(err, "unexpected error")
			if !expectedRules.Equal(gotRules) {
				a.Fail("List of rules did not match", "wanted=%+v got=%+v", expectedRules, gotRules)
			}
			gotRules, err = agg.GetRoleReferenceRules(rbacv1.RoleRef{}, tt.namespace)
			if !expectedRules.Equal(gotRules) {
				a.Fail("List of rules did not match", "wanted=%+v got=%+v", expectedRules, gotRules)
			}
			a.NoError(err, "unexpected error from aggregate resolver.")
		})
	}
}
