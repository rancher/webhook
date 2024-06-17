package resolvers

import (
	"testing"

	"github.com/golang/mock/gomock"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
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
	groupReadPRTB       *apisv3.ProjectRoleTemplateBinding
	groupWritePRTB      *apisv3.ProjectRoleTemplateBinding
	groupAdminPRTB      *apisv3.ProjectRoleTemplateBinding
	group2WritePRTB     *apisv3.ProjectRoleTemplateBinding
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
			Name: "user1-admin",
		},
		ProjectName:      "p-2d2:p-ort",
		UserName:         "user1",
		RoleTemplateName: p.adminRT.Name,
	}
	p.user1AReadNS2PRTB = &apisv3.ProjectRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "user1-read",
		},
		ProjectName:      "p-over:p-ork",
		UserName:         "user1",
		RoleTemplateName: p.readRT.Name,
	}
	p.user1InvalidNS2PRTB = &apisv3.ProjectRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "user1-invalid",
		},
		ProjectName:      "p-over:p-ork",
		UserName:         "user1",
		RoleTemplateName: invalidName,
	}
	p.user2WritePRTB = &apisv3.ProjectRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "user2-write",
		},
		ProjectName:      "p-2d2:p-ort",
		UserName:         "user2",
		RoleTemplateName: p.writeRT.Name,
	}
	p.user2ReadPRTB = &apisv3.ProjectRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "user2-read",
		},
		ProjectName:      "p-2d2:p-ort",
		UserName:         "user2",
		RoleTemplateName: p.readRT.Name,
	}
	p.groupReadPRTB = &apisv3.ProjectRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "group-read",
		},
		ProjectName:      "p-3p0:p-appy",
		GroupName:        authGroup,
		RoleTemplateName: p.readRT.Name,
	}
	p.groupWritePRTB = &apisv3.ProjectRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "group-write",
		},
		ProjectName:        "p-3p0:p-appy",
		GroupPrincipalName: authGroup,
		RoleTemplateName:   p.writeRT.Name,
	}
	p.group2WritePRTB = &apisv3.ProjectRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "group2-write",
		},
		ProjectName:        "p-3p0:p-aul",
		GroupPrincipalName: adminGroup,
		RoleTemplateName:   p.writeRT.Name,
	}
	p.groupAdminPRTB = &apisv3.ProjectRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "group-admin",
		},
		ProjectName:      "p-3p0:p-appy",
		GroupName:        adminGroup,
		RoleTemplateName: p.adminRT.Name,
	}
}

func (p *PRTBResolverSuite) TestPRTBRuleResolver() {
	resolver := p.NewTestPRTBResolver()

	tests := []struct {
		name        string
		user        user.Info
		projectName string
		wantRules   Rules
		wantErr     bool
	}{
		// user with one PRTB in the namespace
		{
			name:        "single PRTB rules",
			user:        NewUserInfo(p.user1AdminPRTB.UserName),
			projectName: p.user1AdminPRTB.ProjectName,
			wantRules:   p.adminRT.Rules,
		},
		// user that belongs to no PRTBs no rules
		{
			name:        "user with no rules",
			user:        NewUserInfo("invalidUser"),
			projectName: p.user1AdminPRTB.ProjectName,
			wantRules:   nil,
		},
		// users with PRTB in different namespace no rules
		{
			name:        "user with no rules in namespace",
			user:        NewUserInfo(p.user2WritePRTB.UserName),
			projectName: p.user1AReadNS2PRTB.ProjectName,
			wantRules:   nil,
		},
		// user with two PRTB
		{
			name:        "user with multiple PRTB",
			user:        NewUserInfo(p.user2ReadPRTB.UserName),
			projectName: p.user2ReadPRTB.ProjectName,
			wantRules:   append(p.readRT.Rules, p.writeRT.Rules...),
		},
		// users with one valid and one invalid PRTB partial rules
		{
			name:        "partial rules",
			user:        NewUserInfo(p.user1InvalidNS2PRTB.UserName),
			projectName: p.user1InvalidNS2PRTB.ProjectName,
			wantRules:   p.readRT.Rules,
			wantErr:     true,
		},
		// user with a PRTB from a group
		{
			name:        "admin rules from group",
			user:        NewUserInfo("invalidUser", adminGroup),
			projectName: p.groupAdminPRTB.ProjectName,
			wantRules:   p.adminRT.Rules,
			wantErr:     false,
		},

		// user with a PRTB from a group in different namespace with different permissions
		{
			name:        "admin rules from group different namespace",
			user:        NewUserInfo("invalidUser", adminGroup),
			projectName: p.group2WritePRTB.ProjectName,
			wantRules:   p.writeRT.Rules,
			wantErr:     false,
		},

		// user with a PRTB from the group in unknown namespace
		{
			name:        "admin rules from group wrong namespace",
			user:        NewUserInfo("invalidUser", adminGroup),
			projectName: "invalid-namespace:invalid-project",
			wantRules:   nil,
			wantErr:     false,
		},

		// user with two PRTBs from the same group
		{
			name:        "partial rules from groups",
			user:        NewUserInfo("invalidUser", authGroup),
			projectName: p.groupAdminPRTB.ProjectName,
			wantRules:   copySlices(p.readRT.Rules, p.writeRT.Rules),
			wantErr:     false,
		},

		// user with three PRTBs from different group
		{
			name:        "multiple groups",
			user:        NewUserInfo("invalidUser", authGroup, adminGroup),
			projectName: p.groupAdminPRTB.ProjectName,
			wantRules:   copySlices(p.readRT.Rules, p.writeRT.Rules, p.adminRT.Rules),
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		p.Run(tt.name, func() {
			namespace, ok := namespaceFromProject(tt.projectName)
			p.Require().True(ok, "failed to split project namespace from project name")
			gotRules, err := resolver.RulesFor(tt.user, namespace)
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

func (p *PRTBResolverSuite) NewTestPRTBResolver() *PRTBRuleResolver {
	ctrl := gomock.NewController(p.T())
	bindings := []*apisv3.ProjectRoleTemplateBinding{p.user1AdminPRTB, p.user1AReadNS2PRTB, p.user1InvalidNS2PRTB,
		p.user2WritePRTB, p.user2ReadPRTB, p.groupAdminPRTB, p.groupReadPRTB, p.groupWritePRTB, p.group2WritePRTB}
	PRTBCache := NewPRTBCache(ctrl, bindings)
	clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
	roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
	roleTemplateCache.EXPECT().Get(p.adminRT.Name).Return(p.adminRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(p.readRT.Name).Return(p.readRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(p.writeRT.Name).Return(p.writeRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(invalidName).Return(nil, errNotFound).AnyTimes()
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	return NewPRTBRuleResolver(PRTBCache, roleResolver)
}

func NewPRTBCache(ctrl *gomock.Controller, bindings []*apisv3.ProjectRoleTemplateBinding) v3.ProjectRoleTemplateBindingCache {
	projectCache := fake.NewMockCacheInterface[*apisv3.ProjectRoleTemplateBinding](ctrl)

	projectCache.EXPECT().AddIndexer(prtbSubjectIndex, gomock.Any()).AnyTimes()

	projectCache.EXPECT().GetByIndex(prtbSubjectIndex, gomock.Any()).DoAndReturn(func(_ string, subject string) ([]*apisv3.ProjectRoleTemplateBinding, error) {
		retList := []*apisv3.ProjectRoleTemplateBinding{}

		// for each binding create a lists of subject keys from the binding
		// if the provided subject matches any of those keys at the binding to the returned list
		for _, binding := range bindings {
			keys, _ := prtbBySubject(binding)
			for _, key := range keys {
				if key == subject {
					retList = append(retList, binding)
					break
				}
			}
		}
		return retList, nil
	}).AnyTimes()

	return projectCache
}
