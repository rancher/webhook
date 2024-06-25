package resolvers

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/wrangler/v2/pkg/generic/fake"
	"github.com/stretchr/testify/suite"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
)

type GRBClusterRuleResolverSuite struct {
	suite.Suite
	userInfo          user.Info
	groupGRB          *v3.GlobalRoleBinding
	errorGroupGRB     *v3.GlobalRoleBinding
	userGRB           *v3.GlobalRoleBinding
	errorUserGRB      *v3.GlobalRoleBinding
	globalUserRules   []rbacv1.PolicyRule
	globalGroupRules  []rbacv1.PolicyRule
	userClusterRules  []rbacv1.PolicyRule
	groupClusterRules []rbacv1.PolicyRule
}

func TestGRBClusterRuleResolver(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(GRBClusterRuleResolverSuite))
}

func (g *GRBClusterRuleResolverSuite) SetupSuite() {
	g.userInfo = NewUserInfo("test-user", "test-group")
	g.groupGRB = &v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "group-grb",
		},
		GlobalRoleName:     "group-gr",
		GroupPrincipalName: "test-group",
	}
	g.errorGroupGRB = &v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "error-group-grb",
		},
		GlobalRoleName:     "error-group-gr",
		GroupPrincipalName: "test-group",
	}
	g.userGRB = &v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "user-grb",
		},
		GlobalRoleName: "user-gr",
		UserName:       "test-user",
	}
	g.errorUserGRB = &v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "error-user-grb",
		},
		GlobalRoleName: "error-user-gr",
		UserName:       "test-user",
	}
	g.globalUserRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"pods"},
			Verbs:     []string{"get"},
		},
	}
	g.globalGroupRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{""},
			Resources: []string{"configmaps"},
			Verbs:     []string{"get"},
		},
	}

	g.userClusterRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{"apps"},
			Resources: []string{"deployments"},
			Verbs:     []string{"get"},
		},
	}
	g.groupClusterRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{"apps"},
			Resources: []string{"statefulsets"},
			Verbs:     []string{"get"},
		},
	}
}

func (g *GRBClusterRuleResolverSuite) TestGRBClusterRuleResolver() {
	type testState struct {
		grCache  *fake.MockNonNamespacedCacheInterface[*v3.GlobalRole]
		grbCache *fake.MockNonNamespacedCacheInterface[*v3.GlobalRoleBinding]
		rtCache  *fake.MockNonNamespacedCacheInterface[*v3.RoleTemplate]
	}

	tests := []struct {
		name      string
		setup     func(state testState)
		namespace string
		wantRules []rbacv1.PolicyRule
		wantError bool
	}{
		{
			name:      "test rule resolution, valid + invalid user/group bindings",
			namespace: "",
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.userInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{g.userGRB, g.errorUserGRB}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.userInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{g.groupGRB, g.errorGroupGRB}, nil)
				state.rtCache.EXPECT().Get("test-user-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-user-rt",
					},
					Rules: g.userClusterRules,
				}, nil)
				state.rtCache.EXPECT().Get("test-group-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-group-rt",
					},
					Rules: g.groupClusterRules,
				}, nil)

				state.grCache.EXPECT().Get(g.userGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.userGRB.GlobalRoleName,
					},
					Rules:                 g.globalUserRules,
					InheritedClusterRoles: []string{"test-user-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.groupGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.groupGRB.GlobalRoleName,
					},
					Rules:                 g.globalGroupRules,
					InheritedClusterRoles: []string{"test-group-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.errorUserGRB.GlobalRoleName).Return(nil, fmt.Errorf("server unavailable"))
				state.grCache.EXPECT().Get(g.errorGroupGRB.GlobalRoleName).Return(nil, fmt.Errorf("server unavailable"))
			},
			wantRules: append(g.userClusterRules, g.groupClusterRules...),
			wantError: true,
		},
		{
			name:      "test state resolution group indexer error",
			namespace: "",
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.userInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{g.userGRB, g.errorUserGRB}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.userInfo.GetGroups()[0], "")).Return(nil, fmt.Errorf("server unavailable"))
				state.rtCache.EXPECT().Get("test-user-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-user-rt",
					},
					Rules: g.userClusterRules,
				}, nil)
				state.grCache.EXPECT().Get(g.userGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.userGRB.GlobalRoleName,
					},
					Rules:                 g.globalUserRules,
					InheritedClusterRoles: []string{"test-user-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.errorUserGRB.GlobalRoleName).Return(nil, fmt.Errorf("server unavailable"))

			},
			wantRules: g.userClusterRules,
			wantError: true,
		},
		{
			name:      "test state resolution user indexer error",
			namespace: "",
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.userInfo.GetName(), "")).Return(nil, fmt.Errorf("server unavailable"))
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.userInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{g.groupGRB, g.errorGroupGRB}, nil)
				state.rtCache.EXPECT().Get("test-group-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-group-rt",
					},
					Rules: g.groupClusterRules,
				}, nil)

				state.grCache.EXPECT().Get(g.groupGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.groupGRB.GlobalRoleName,
					},
					Rules:                 g.globalGroupRules,
					InheritedClusterRoles: []string{"test-group-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.errorGroupGRB.GlobalRoleName).Return(nil, fmt.Errorf("server unavailable"))

			},
			wantRules: g.groupClusterRules,
			wantError: true,
		},
		{
			name:      "test state resolution local cluster",
			namespace: "local",
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.userInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{g.userGRB, g.errorUserGRB}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.userInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{g.groupGRB, g.errorGroupGRB}, nil)

				state.grCache.EXPECT().Get(g.userGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.userGRB.GlobalRoleName,
					},
					Rules:                 g.globalUserRules,
					InheritedClusterRoles: []string{"test-user-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.groupGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.groupGRB.GlobalRoleName,
					},
					Rules:                 g.globalGroupRules,
					InheritedClusterRoles: []string{"test-group-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.errorUserGRB.GlobalRoleName).Return(nil, fmt.Errorf("server unavailable"))
				state.grCache.EXPECT().Get(g.errorGroupGRB.GlobalRoleName).Return(nil, fmt.Errorf("server unavailable"))
			},

			wantRules: append(g.globalUserRules, g.globalGroupRules...),
			wantError: true,
		},
		{
			name:      "test state resolution non-local cluster",
			namespace: "not-local",
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.userInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{g.userGRB}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.userInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{g.groupGRB}, nil)

				state.grCache.EXPECT().Get(g.userGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.userGRB.GlobalRoleName,
					},
					Rules:                 g.globalUserRules,
					InheritedClusterRoles: []string{"test-user-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.groupGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.groupGRB.GlobalRoleName,
					},
					Rules:                 g.globalGroupRules,
					InheritedClusterRoles: []string{"test-group-rt"},
				}, nil)
				state.rtCache.EXPECT().Get("test-user-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-user-rt",
					},
					Rules: g.userClusterRules,
				}, nil)
				state.rtCache.EXPECT().Get("test-group-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-group-rt",
					},
					Rules: g.groupClusterRules,
				}, nil)

			},

			wantRules: append(g.userClusterRules, g.groupClusterRules...),
			wantError: false,
		},
		{
			name:      "test state resolution no error, no namespace",
			namespace: "",
			setup: func(state testState) {
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetUserKey(g.userInfo.GetName(), "")).Return([]*v3.GlobalRoleBinding{g.userGRB}, nil)
				state.grbCache.EXPECT().GetByIndex(grbSubjectIndex, GetGroupKey(g.userInfo.GetGroups()[0], "")).Return([]*v3.GlobalRoleBinding{g.groupGRB}, nil)

				state.grCache.EXPECT().Get(g.userGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.userGRB.GlobalRoleName,
					},
					Rules:                 g.globalUserRules,
					InheritedClusterRoles: []string{"test-user-rt"},
				}, nil)
				state.grCache.EXPECT().Get(g.groupGRB.GlobalRoleName).Return(&v3.GlobalRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: g.groupGRB.GlobalRoleName,
					},
					Rules:                 g.globalGroupRules,
					InheritedClusterRoles: []string{"test-group-rt"},
				}, nil)
				state.rtCache.EXPECT().Get("test-user-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-user-rt",
					},
					Rules: g.userClusterRules,
				}, nil)
				state.rtCache.EXPECT().Get("test-group-rt").Return(&v3.RoleTemplate{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-group-rt",
					},
					Rules: g.groupClusterRules,
				}, nil)

			},

			wantRules: append(g.userClusterRules, g.groupClusterRules...),
			wantError: false,
		},
	}

	for _, test := range tests {
		test := test
		g.Run(test.name, func() {
			ctrl := gomock.NewController(g.T())
			grbCache := fake.NewMockNonNamespacedCacheInterface[*v3.GlobalRoleBinding](ctrl)
			grbCache.EXPECT().AddIndexer(grbSubjectIndex, gomock.Any()).AnyTimes()

			rtCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
			grCache := fake.NewMockNonNamespacedCacheInterface[*v3.GlobalRole](ctrl)
			state := testState{
				grCache:  grCache,
				grbCache: grbCache,
				rtCache:  rtCache,
			}

			if test.setup != nil {
				test.setup(state)
			}

			grResolver := auth.NewGlobalRoleResolver(auth.NewRoleTemplateResolver(state.rtCache, nil), state.grCache)
			grbResolvers := NewGRBRuleResolvers(state.grbCache, grResolver)

			rules, err := grbResolvers.ICRResolver.RulesFor(g.userInfo, test.namespace)
			g.Require().Len(rules, len(test.wantRules))
			for _, rule := range test.wantRules {
				g.Require().Contains(rules, rule)
			}
			if test.wantError {
				g.Require().Error(err)
			} else {
				g.Require().NoError(err)
			}
		})
	}
}

func (g *GRBClusterRuleResolverSuite) Test_grbSubjectIndexer() {
	tests := []struct {
		name        string
		grb         *v3.GlobalRoleBinding
		wantIndexes []string
		wantError   bool
	}{
		{
			name: "user key",
			grb: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
				UserName: "test-user",
			},
			wantIndexes: []string{"user:test-user-"},
			wantError:   false,
		},
		{
			name: "group key",
			grb: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
				GroupPrincipalName: "test-group",
			},
			wantIndexes: []string{"group:test-group-"},
			wantError:   false,
		},
		{
			name: "user + group key",
			grb: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
				UserName:           "test-user",
				GroupPrincipalName: "test-group",
			},
			wantIndexes: []string{"user:test-user-"},
			wantError:   false,
		},
		{
			name: "no subject",
			grb: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
			},
			wantIndexes: nil,
			wantError:   false,
		},
	}
	for _, test := range tests {
		test := test
		g.Run(test.name, func() {
			indexes, err := grbBySubject(test.grb)
			if test.wantError {
				g.Require().Error(err)
			} else {
				g.Require().NoError(err)
				g.Require().Len(indexes, len(test.wantIndexes))
				for _, index := range test.wantIndexes {
					g.Require().Contains(indexes, index)
				}
			}
		})
	}

}
