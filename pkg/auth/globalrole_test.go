package auth_test

import (
	"fmt"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	globalRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"test.cattle.io",
			},
			Resources: []string{
				"global",
			},
			Verbs: []string{
				"*",
			},
		},
	}
	noInheritRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"test.cattle.io",
			},
			Resources: []string{
				"notInherited",
			},
			Verbs: []string{
				"*",
			},
		},
	}
	firstRTRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"test.cattle.io",
			},
			Resources: []string{
				"firstRT",
			},
			Verbs: []string{
				"*",
			},
		},
	}
	secondRTRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"test.cattle.io",
			},
			Resources: []string{
				"secondRT",
			},
			Verbs: []string{
				"*",
			},
		},
	}
	adminRTRules = []rbacv1.PolicyRule{
		{
			APIGroups: []string{
				"*",
			},
			Resources: []string{
				"*",
			},
			Verbs: []string{
				"*",
			},
		},
		{
			NonResourceURLs: []string{
				"*",
			},
			Verbs: []string{
				"*",
			},
		},
	}

	noInhertRT = &v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "no-inhert-rt",
		},
		Rules: noInheritRules,
	}
	firstRT = &v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "first-rt",
		},
		Rules:             firstRTRules,
		RoleTemplateNames: []string{secondRT.Name},
	}
	secondRT = &v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "second-rt",
		},
		Rules: secondRTRules,
	}
	adminRT = &v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-owner",
		},
		Rules: adminRTRules,
	}
)

func TestGlobalRulesFromRole(t *testing.T) {
	type testState struct {
		rtCacheMock *fake.MockNonNamespacedCacheInterface[*v3.RoleTemplate]
	}
	tests := []struct {
		name       string
		globalRole *v3.GlobalRole
		stateSetup func(state testState)
		wantRules  []rbacv1.PolicyRule
	}{
		{
			name: "test basic GR",
			globalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				Rules: globalRules,
			},
			wantRules: globalRules,
		},
		{
			name:       "test nil global role",
			globalRole: nil,
			wantRules:  nil,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			rtCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
			state := testState{
				rtCacheMock: rtCache,
			}
			if test.stateSetup != nil {
				test.stateSetup(state)
			}
			grResolver := auth.NewGlobalRoleResolver(auth.NewRoleTemplateResolver(state.rtCacheMock, nil), nil)
			rules := grResolver.GlobalRulesFromRole(test.globalRole)

			require.Len(t, rules, len(test.wantRules))
			for _, wantRule := range test.wantRules {
				require.Contains(t, rules, wantRule)
			}
		})
	}
}

func TestClusterRulesFromRole(t *testing.T) {
	type testState struct {
		rtCacheMock *fake.MockNonNamespacedCacheInterface[*v3.RoleTemplate]
	}
	tests := []struct {
		name       string
		globalRole *v3.GlobalRole
		stateSetup func(state testState)
		wantRules  []rbacv1.PolicyRule
		wantErr    bool
	}{
		{
			name: "test basic GR",
			globalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				Rules: globalRules,
			},
			wantRules: nil,
		},
		{
			name: "test global rules + role template",
			globalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				Rules:                 globalRules,
				InheritedClusterRoles: []string{noInhertRT.Name},
			},
			stateSetup: func(state testState) {
				state.rtCacheMock.EXPECT().Get(noInhertRT.Name).Return(noInhertRT, nil)
			},
			wantRules: noInheritRules,
		},
		{
			name: "test global rules + multiple role templates",
			globalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				Rules:                 globalRules,
				InheritedClusterRoles: []string{noInhertRT.Name, firstRT.Name},
			},
			stateSetup: func(state testState) {
				state.rtCacheMock.EXPECT().Get(noInhertRT.Name).Return(noInhertRT, nil)
				state.rtCacheMock.EXPECT().Get(firstRT.Name).Return(firstRT, nil)
				state.rtCacheMock.EXPECT().Get(secondRT.Name).Return(secondRT, nil)
			},
			wantRules: append(append(noInheritRules, firstRTRules...), secondRTRules...),
		},
		{
			name: "test restricted admin gr",
			globalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "restricted-admin",
				},
				Rules:                 globalRules,
				InheritedClusterRoles: []string{},
			},
			stateSetup: func(state testState) {
				state.rtCacheMock.EXPECT().Get("cluster-owner").Return(adminRT, nil)
			},
			wantRules: adminRTRules,
		},

		{
			name: "test rt resolver error",
			globalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				Rules:                 globalRules,
				InheritedClusterRoles: []string{noInhertRT.Name, "error"},
			},
			stateSetup: func(state testState) {
				state.rtCacheMock.EXPECT().Get(noInhertRT.Name).Return(noInhertRT, nil)
				state.rtCacheMock.EXPECT().Get("error").Return(nil, fmt.Errorf("server not available"))
			},
			wantErr: true,
		},
		{
			name:       "test nil global role",
			globalRole: nil,
			wantErr:    false,
			wantRules:  nil,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			rtCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
			state := testState{
				rtCacheMock: rtCache,
			}
			if test.stateSetup != nil {
				test.stateSetup(state)
			}
			grResolver := auth.NewGlobalRoleResolver(auth.NewRoleTemplateResolver(state.rtCacheMock, nil), nil)
			rules, err := grResolver.ClusterRulesFromRole(test.globalRole)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Len(t, rules, len(test.wantRules))
			for _, wantRule := range test.wantRules {
				require.Contains(t, rules, wantRule)
			}
		})
	}
}

func TestGetRoleTemplatesForGlobalRole(t *testing.T) {
	type testState struct {
		rtCacheMock *fake.MockNonNamespacedCacheInterface[*v3.RoleTemplate]
	}
	tests := []struct {
		name              string
		globalRole        *v3.GlobalRole
		stateSetup        func(state testState)
		wantRoleTemplates []*v3.RoleTemplate
		wantErr           bool
	}{
		{
			name: "test top-level-only rts",
			globalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				InheritedClusterRoles: []string{firstRT.Name, noInhertRT.Name},
			},
			stateSetup: func(state testState) {
				state.rtCacheMock.EXPECT().Get(firstRT.Name).Return(firstRT, nil)
				state.rtCacheMock.EXPECT().Get(noInhertRT.Name).Return(noInhertRT, nil)
			},
			wantRoleTemplates: []*v3.RoleTemplate{firstRT, noInhertRT},
		},
		{
			name: "test error rt",
			globalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				InheritedClusterRoles: []string{noInhertRT.Name, "error"},
			},
			stateSetup: func(state testState) {
				state.rtCacheMock.EXPECT().Get(noInhertRT.Name).Return(noInhertRT, nil).AnyTimes()
				state.rtCacheMock.EXPECT().Get("error").Return(nil, fmt.Errorf("server unavailable"))
			},
			wantErr: true,
		},
		{
			name:              "test nil global role",
			globalRole:        nil,
			wantErr:           false,
			wantRoleTemplates: nil,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			rtCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
			state := testState{
				rtCacheMock: rtCache,
			}
			if test.stateSetup != nil {
				test.stateSetup(state)
			}
			grResolver := auth.NewGlobalRoleResolver(auth.NewRoleTemplateResolver(state.rtCacheMock, nil), nil)
			roleTemplates, err := grResolver.GetRoleTemplatesForGlobalRole(test.globalRole)
			if test.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Len(t, roleTemplates, len(test.wantRoleTemplates))
			for _, wantRoleTemplate := range test.wantRoleTemplates {
				require.Contains(t, roleTemplates, wantRoleTemplate)
			}
		})
	}
}
