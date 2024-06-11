package resolvers

import (
	"testing"

	"github.com/golang/mock/gomock"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/wrangler/v2/pkg/generic/fake"
	"github.com/stretchr/testify/suite"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/user"
)

type CRTBResolverSuite struct {
	suite.Suite
	adminRT             *apisv3.RoleTemplate
	readRT              *apisv3.RoleTemplate
	writeRT             *apisv3.RoleTemplate
	user1AdminCRTB      *apisv3.ClusterRoleTemplateBinding
	user1AReadNS2CRTB   *apisv3.ClusterRoleTemplateBinding
	user1InvalidNS2CRTB *apisv3.ClusterRoleTemplateBinding
	user2WriteCRTB      *apisv3.ClusterRoleTemplateBinding
	user2ReadCRTB       *apisv3.ClusterRoleTemplateBinding
	groupAdminCRTB      *apisv3.ClusterRoleTemplateBinding
	groupWriteCRTB      *apisv3.ClusterRoleTemplateBinding
	group2WriteCRTB     *apisv3.ClusterRoleTemplateBinding
	groupReadCRTB       *apisv3.ClusterRoleTemplateBinding
}

func TestCRTBResolver(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(CRTBResolverSuite))
}

func (c *CRTBResolverSuite) SetupSuite() {
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
	c.readRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "read-role",
		},
		DisplayName: "Read Role",
		Rules:       []rbacv1.PolicyRule{ruleReadPods, ruleReadServices},
		Context:     "cluster",
	}
	c.adminRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		DisplayName:    "Admin Role",
		Rules:          []rbacv1.PolicyRule{ruleAdmin},
		Builtin:        true,
		Administrative: true,
		Context:        "cluster",
	}
	c.writeRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "locked-role",
		},
		DisplayName: "Locked Role",
		Rules:       []rbacv1.PolicyRule{ruleWriteNodes},
		Locked:      true,
		Context:     "cluster",
	}
	c.user1AdminCRTB = &apisv3.ClusterRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "user1-admin",
		},
		ClusterName:      "namespace1",
		UserName:         "user1",
		RoleTemplateName: c.adminRT.Name,
	}
	c.user1AReadNS2CRTB = &apisv3.ClusterRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "user1-read",
		},
		ClusterName:      "namespace2",
		UserName:         "user1",
		RoleTemplateName: c.readRT.Name,
	}
	c.user1InvalidNS2CRTB = &apisv3.ClusterRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "user1-invalid",
		},
		ClusterName:      "namespace2",
		UserName:         "user1",
		RoleTemplateName: invalidName,
	}
	c.user2WriteCRTB = &apisv3.ClusterRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "user2-write",
		},
		ClusterName:      "namespace1",
		UserName:         "user2",
		RoleTemplateName: c.writeRT.Name,
	}
	c.user2ReadCRTB = &apisv3.ClusterRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "user2-read",
		},
		ClusterName:      "namespace1",
		UserName:         "user2",
		RoleTemplateName: c.readRT.Name,
	}

	c.groupWriteCRTB = &apisv3.ClusterRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "group-write",
		},
		ClusterName:      "namespace1",
		GroupName:        authGroup,
		RoleTemplateName: c.writeRT.Name,
	}
	c.groupReadCRTB = &apisv3.ClusterRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "group-read",
		},
		ClusterName:      "namespace1",
		GroupName:        authGroup,
		RoleTemplateName: c.readRT.Name,
	}
	c.group2WriteCRTB = &apisv3.ClusterRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "group2-write",
		},
		ClusterName:        "namespace2",
		GroupPrincipalName: adminGroup,
		RoleTemplateName:   c.writeRT.Name,
	}
	c.groupAdminCRTB = &apisv3.ClusterRoleTemplateBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "group-admin",
		},
		ClusterName:      "namespace1",
		GroupName:        adminGroup,
		RoleTemplateName: c.adminRT.Name,
	}
}

func (c *CRTBResolverSuite) TestCRTBRuleResolver() {
	resolver := c.NewTestCRTBResolver()
	tests := []struct {
		name        string
		user        user.Info
		clusterName string
		wantRules   Rules
		wantErr     bool
	}{
		// user with one CRTB in the namespace
		{
			name:        "single CRTB rules",
			user:        NewUserInfo(c.user1AdminCRTB.UserName),
			clusterName: c.user1AdminCRTB.ClusterName,
			wantRules:   c.adminRT.Rules,
		},
		// user that belongs to no CRTBs no rules
		{
			name:        "user with no rules",
			user:        NewUserInfo("invalidUser"),
			clusterName: c.user1AdminCRTB.ClusterName,
			wantRules:   nil,
		},
		// users with CRTB in different namespace no rules
		{
			name:        "user with no rules in namespace",
			user:        NewUserInfo(c.user2WriteCRTB.UserName),
			clusterName: c.user1AReadNS2CRTB.ClusterName,
			wantRules:   nil,
		},
		// user with two CRTB
		{
			name:        "user with multiple CRTB",
			user:        NewUserInfo(c.user2ReadCRTB.UserName),
			clusterName: c.user2ReadCRTB.ClusterName,
			wantRules:   copySlices(c.readRT.Rules, c.writeRT.Rules),
		},
		// users with one valid and one invalid CRTB partial rules
		{
			name:        "partial rules",
			user:        NewUserInfo(c.user1InvalidNS2CRTB.UserName),
			clusterName: c.user1InvalidNS2CRTB.ClusterName,
			wantRules:   c.readRT.Rules,
			wantErr:     true,
		},
		// user with a CRTB from a group
		{
			name:        "admin rules from group",
			user:        NewUserInfo("invalidUser", adminGroup),
			clusterName: c.groupAdminCRTB.ClusterName,
			wantRules:   c.adminRT.Rules,
			wantErr:     false,
		},

		// user with a CRTB from a group in different namespace with different permissions
		{
			name:        "admin rules from group different namespace",
			user:        NewUserInfo("invalidUser", adminGroup),
			clusterName: c.group2WriteCRTB.ClusterName,
			wantRules:   c.writeRT.Rules,
			wantErr:     false,
		},

		// user with CRTB from a group in unknown namespace
		{
			name:        "admin rules from group wrong namespace",
			user:        NewUserInfo("invalidUser", adminGroup),
			clusterName: "invalid-namespace",
			wantRules:   nil,
			wantErr:     false,
		},

		// user with two CRTBs from the same group
		{
			name:        "partial rules from groups",
			user:        NewUserInfo("invalidUser", authGroup),
			clusterName: c.groupAdminCRTB.ClusterName,
			wantRules:   copySlices(c.readRT.Rules, c.writeRT.Rules),
			wantErr:     false,
		},

		// user with three CRTBs from different groups
		{
			name:        "multiple groups",
			user:        NewUserInfo("invalidUser", authGroup, adminGroup),
			clusterName: c.groupAdminCRTB.ClusterName,
			wantRules:   copySlices(c.readRT.Rules, c.writeRT.Rules, c.adminRT.Rules),
			wantErr:     false,
		},
	}
	for _, tt := range tests {
		c.Run(tt.name, func() {
			gotRules, err := resolver.RulesFor(tt.user, tt.clusterName)
			if tt.wantErr {
				c.Errorf(err, "CRTBRuleResolver.RulesFor() error = %v, wantErr %v", err, tt.wantErr)
				// still check result because function is suppose to return partial results.

				if !tt.wantRules.Equal(gotRules) {
					c.Fail("List of rules did not match", "wanted=%+v got=%+v", tt.wantRules, gotRules)
				}
				return
			}
			c.NoError(err, "unexpected error")
			if !tt.wantRules.Equal(gotRules) {
				c.Fail("List of rules did not match", "wanted=%+v got=%+v", tt.wantRules, gotRules)
			}
		})
	}
}
func (c *CRTBResolverSuite) NewTestCRTBResolver() *CRTBRuleResolver {
	ctrl := gomock.NewController(c.T())
	bindings := []*apisv3.ClusterRoleTemplateBinding{c.user1AdminCRTB, c.user1AReadNS2CRTB, c.user1InvalidNS2CRTB,
		c.user2WriteCRTB, c.user2ReadCRTB, c.groupAdminCRTB, c.groupReadCRTB, c.groupWriteCRTB, c.group2WriteCRTB}
	crtbCache := NewCRTBCache(ctrl, bindings)
	clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
	roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
	roleTemplateCache.EXPECT().Get(c.adminRT.Name).Return(c.adminRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(c.readRT.Name).Return(c.readRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(c.writeRT.Name).Return(c.writeRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(invalidName).Return(nil, errNotFound).AnyTimes()
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache, nil)
	return NewCRTBRuleResolver(crtbCache, roleResolver)
}

func NewCRTBCache(ctrl *gomock.Controller, bindings []*apisv3.ClusterRoleTemplateBinding) v3.ClusterRoleTemplateBindingCache {
	clusterCache := fake.NewMockCacheInterface[*apisv3.ClusterRoleTemplateBinding](ctrl)

	clusterCache.EXPECT().Get(gomock.Any(), gomock.Any()).DoAndReturn(func(namespace, name string) (*apisv3.ClusterRoleTemplateBinding, error) {
		for _, binding := range bindings {
			if binding.Namespace == namespace && binding.Name == name {
				return binding, nil
			}
		}
		return nil, errNotFound
	}).AnyTimes()
	clusterCache.EXPECT().AddIndexer(crtbSubjectIndex, gomock.Any()).AnyTimes()
	clusterCache.EXPECT().GetByIndex(crtbSubjectIndex, gomock.Any()).DoAndReturn(func(_ string, subject string) ([]*apisv3.ClusterRoleTemplateBinding, error) {
		retList := []*apisv3.ClusterRoleTemplateBinding{}
		// for each binding create a lists of subject keys from the binding
		// if the provided subject matches any of those keys at the binding to the returned list
		for _, binding := range bindings {
			keys, _ := crtbBySubject(binding)
			for _, key := range keys {
				if key == subject {
					retList = append(retList, binding)
					break
				}
			}
		}
		return retList, nil
	}).AnyTimes()

	return clusterCache
}
