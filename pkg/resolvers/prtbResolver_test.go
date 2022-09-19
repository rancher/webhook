package resolvers_test

import (
	"testing"

	"github.com/golang/mock/gomock"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/fakes"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resolvers"
	"github.com/stretchr/testify/suite"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
)

type PRTBResolverSuite struct {
	suite.Suite
	adminRT             *apisv3.RoleTemplate
	readRT              *apisv3.RoleTemplate
	writeRT             *apisv3.RoleTemplate
	user1AdminPRTB      *apisv3.ProjectRoleTemplateBinding
	user1AReadNS2PRTB   *apisv3.ProjectRoleTemplateBinding
	user1InvalidNS2PRTB *apisv3.ProjectRoleTemplateBinding
	user2WritePRTB      *apisv3.ProjectRoleTemplateBinding
	user2ReadPRTB       *apisv3.ProjectRoleTemplateBinding
}

func TestPRTBResolver(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(PRTBResolverSuite))
}

func (p *PRTBResolverSuite) SetupSuite() {
	ruleReadPods := rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"pods"},
	}
	ruleReadServices := rbacv1.PolicyRule{
		Verbs:     []string{"GET", "WATCH"},
		APIGroups: []string{"v1"},
		Resources: []string{"services"},
	}
	ruleWriteNodes := rbacv1.PolicyRule{
		Verbs:     []string{"PUT", "CREATE", "UPDATE"},
		APIGroups: []string{"v1"},
		Resources: []string{"nodes"},
	}
	ruleAdmin := rbacv1.PolicyRule{
		Verbs:     []string{"*"},
		APIGroups: []string{"*"},
		Resources: []string{"*"},
	}
	p.readRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "read-role",
		},
		DisplayName: "Read Role",
		Rules:       []rbacv1.PolicyRule{ruleReadPods, ruleReadServices},
		Context:     "project",
	}
	p.adminRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		DisplayName:    "Admin Role",
		Rules:          []rbacv1.PolicyRule{ruleAdmin},
		Builtin:        true,
		Administrative: true,
		Context:        "project",
	}
	p.writeRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "locked-role",
		},
		DisplayName: "Locked Role",
		Rules:       []rbacv1.PolicyRule{ruleWriteNodes},
		Locked:      true,
		Context:     "project",
	}
	p.user1AdminPRTB = &apisv3.ProjectRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user1-admin",
			Namespace: "namespace1",
		},
		UserName:         "user1",
		RoleTemplateName: p.adminRT.Name,
	}
	p.user1AReadNS2PRTB = &apisv3.ProjectRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user1-read",
			Namespace: "namespace2",
		},
		UserName:         "user1",
		RoleTemplateName: p.readRT.Name,
	}
	p.user1InvalidNS2PRTB = &apisv3.ProjectRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user1-invalid",
			Namespace: "namespace2",
		},
		UserName:         "user1",
		RoleTemplateName: invalidName,
	}
	p.user2WritePRTB = &apisv3.ProjectRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user2-write",
			Namespace: "namespace1",
		},
		UserName:         "user2",
		RoleTemplateName: p.writeRT.Name,
	}
	p.user2ReadPRTB = &apisv3.ProjectRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "user2-read",
			Namespace: "namespace1",
		},
		UserName:         "user2",
		RoleTemplateName: p.readRT.Name,
	}
}

func (p *PRTBResolverSuite) TestPRTBRuleResolver() {
	resolver := p.NewTestPRTBResolver()

	tests := []struct {
		name      string
		user      user.Info
		namespace string
		wantRules Rules
		wantErr   bool
	}{
		// user with one PRTB in the namespace
		{
			name:      "single PRTB rules",
			user:      NewUserInfo(p.user1AdminPRTB.UserName),
			namespace: p.user1AdminPRTB.Namespace,
			wantRules: p.adminRT.Rules,
		},
		// user that belongs to no PRTBs no rules
		{
			name:      "user with no rules",
			user:      NewUserInfo("invalidUser"),
			namespace: p.user1AdminPRTB.Namespace,
			wantRules: nil,
		},
		// users with PRTB in different namespace no rules
		{
			name:      "user with no rules in namespace",
			user:      NewUserInfo(p.user2WritePRTB.UserName),
			namespace: p.user1AReadNS2PRTB.Namespace,
			wantRules: nil,
		},
		// user with two PRTB
		{
			name:      "user with multiple PRTB",
			user:      NewUserInfo(p.user2ReadPRTB.UserName),
			namespace: p.user2ReadPRTB.Namespace,
			wantRules: append(p.readRT.Rules, p.writeRT.Rules...),
		},
		// users with one valid and one invalid PRTB partial rules
		{
			name:      "partial rules",
			user:      NewUserInfo(p.user1InvalidNS2PRTB.UserName),
			namespace: p.user1InvalidNS2PRTB.Namespace,
			wantRules: p.readRT.Rules,
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		p.Run(tt.name, func() {
			gotRules, err := resolver.RulesFor(tt.user, tt.namespace)
			if tt.wantErr {
				p.Errorf(err, "PRTBRuleResolver.RulesFor() error = %v, wantErr %v", err, tt.wantErr)
				// still check result because function is suppose to return partial results.

				if !tt.wantRules.Equal(gotRules) {
					p.Fail("List of rules did not match", "wanted=%+v got=%+v", tt.wantRules, gotRules)
				}
				return
			}
			p.NoError(err, "unexpected error")
			if !tt.wantRules.Equal(gotRules) {
				p.Fail("List of rules did not match", "wanted=%+v got=%+v", tt.wantRules, gotRules)
			}
		})
	}
}

func (p *PRTBResolverSuite) NewTestPRTBResolver() *resolvers.PRTBRuleResolver {
	ctrl := gomock.NewController(p.T())
	bindings := []*apisv3.ProjectRoleTemplateBinding{p.user1AdminPRTB, p.user1AReadNS2PRTB, p.user1InvalidNS2PRTB, p.user2WritePRTB, p.user2ReadPRTB}
	PRTBCache := NewPRTBCache(ctrl, bindings)
	clusterRoleCache := fakes.NewMockClusterRoleCache(ctrl)
	roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
	roleTemplateCache.EXPECT().Get(p.adminRT.Name).Return(p.adminRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(p.readRT.Name).Return(p.readRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(p.writeRT.Name).Return(p.writeRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(invalidName).Return(nil, errNotFound).AnyTimes()
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	return resolvers.NewPRTBRuleResolver(PRTBCache, roleResolver)
}

func NewPRTBCache(ctrl *gomock.Controller, bindings []*apisv3.ProjectRoleTemplateBinding) v3.ProjectRoleTemplateBindingCache {
	projectCache := fakes.NewMockProjectRoleTemplateBindingCache(ctrl)

	projectCache.EXPECT().Get(gomock.Any(), gomock.Any()).DoAndReturn(func(namespace, name string) (*apisv3.ProjectRoleTemplateBinding, error) {
		for _, binding := range bindings {
			if binding.Namespace == namespace && binding.Name == name {
				return binding, nil
			}
		}
		return nil, errNotFound
	}).AnyTimes()

	projectCache.EXPECT().List(gomock.Any(), gomock.Any()).DoAndReturn(func(namespace string, _ interface{}) ([]*apisv3.ProjectRoleTemplateBinding, error) {
		retList := []*apisv3.ProjectRoleTemplateBinding{}
		for _, binding := range bindings {
			if binding.Namespace == namespace {
				retList = append(retList, binding)
			}
		}
		return retList, nil
	}).AnyTimes()

	return projectCache
}
