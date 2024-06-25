package clusterroletemplatebinding_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/resolvers"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/clusterroletemplatebinding"
	"github.com/rancher/wrangler/v2/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	v1authentication "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const (
	grbOwnerLabel    = "authz.management.cattle.io/grb-owner"
	defaultClusterID = "c-namespace"
)

type ClusterRoleTemplateBindingSuite struct {
	suite.Suite
	adminRT                   *apisv3.RoleTemplate
	readNodesRT               *apisv3.RoleTemplate
	lockedRT                  *apisv3.RoleTemplate
	projectRT                 *apisv3.RoleTemplate
	externalRulesWriteNodesRT *apisv3.RoleTemplate
	externalClusterRoleRT     *v3.RoleTemplate
	adminCR                   *rbacv1.ClusterRole
	writeNodeCR               *rbacv1.ClusterRole
	readPodsCR                *rbacv1.ClusterRole
	readServiceRole           *rbacv1.Role
}

func TestClusterRoleTemplateBindings(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(ClusterRoleTemplateBindingSuite))
}

func (c *ClusterRoleTemplateBindingSuite) SetupSuite() {
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
	c.readNodesRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "read-role",
		},
		DisplayName: "Read Role",
		Rules:       []rbacv1.PolicyRule{ruleReadPods, ruleWriteNodes},
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
	c.externalRulesWriteNodesRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "external-rule-write-nodes",
		},
		DisplayName:    "External Role",
		ExternalRules:  []rbacv1.PolicyRule{ruleWriteNodes},
		External:       true,
		Builtin:        true,
		Administrative: true,
		Context:        "cluster",
	}
	c.externalClusterRoleRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "read-pods-role",
		},
		DisplayName:    "External Role",
		External:       true,
		Builtin:        true,
		Administrative: true,
		Context:        "cluster",
	}
	c.lockedRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "locked-role",
		},
		DisplayName: "Locked Role",
		Rules:       []rbacv1.PolicyRule{ruleReadServices},
		Locked:      true,
		Context:     "cluster",
	}
	c.projectRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "project-role",
		},
		DisplayName: "Project Role",
		Rules:       []rbacv1.PolicyRule{ruleReadServices},
		Context:     "project",
	}
	c.adminCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		Rules: []rbacv1.PolicyRule{ruleAdmin},
	}
	c.writeNodeCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "write-role"},
		Rules:      []rbacv1.PolicyRule{ruleWriteNodes, ruleWriteNodes},
	}
	c.readServiceRole = &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: "namespace1", Name: "read-service"},
		Rules:      []rbacv1.PolicyRule{ruleReadServices},
	}
	c.readPodsCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "read-pods-role"},
		Rules:      []rbacv1.PolicyRule{ruleReadPods},
	}
}

func (c *ClusterRoleTemplateBindingSuite) Test_PrivilegeEscalation() {
	const adminUser = "admin-userid"
	const testUser = "test-userid"
	const errorUser = "error-userid"
	const crtbUser = "escalate-userid"
	roles := []*rbacv1.Role{c.readServiceRole}
	clusterRoles := []*rbacv1.ClusterRole{c.adminCR, c.writeNodeCR}
	roleBindings := []*rbacv1.RoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: c.readServiceRole.Namespace},
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: testUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: c.readServiceRole.Name},
		},
	}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
				{Kind: rbacv1.UserKind, Name: errorUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: c.adminCR.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(roles, roleBindings, clusterRoles, clusterRoleBindings)

	ctrl := gomock.NewController(c.T())
	roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
	roleTemplateCache.EXPECT().Get(c.adminRT.Name).Return(c.adminRT, nil).AnyTimes()
	clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	crtbCache := fake.NewMockCacheInterface[*apisv3.ClusterRoleTemplateBinding](ctrl)
	crtbCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any())
	crtbCache.EXPECT().GetByIndex(gomock.Any(), resolvers.GetUserKey(crtbUser, newDefaultCRTB().ClusterName)).Return([]*apisv3.ClusterRoleTemplateBinding{
		{
			UserName:         crtbUser,
			RoleTemplateName: c.adminRT.Name,
		},
	}, nil).AnyTimes()
	crtbCache.EXPECT().GetByIndex(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	clusterCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.Cluster](ctrl)
	clusterCache.EXPECT().Get(defaultClusterID).Return(&apisv3.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaultClusterID,
		},
	}, nil).AnyTimes()

	crtbResolver := resolvers.NewCRTBRuleResolver(crtbCache, roleResolver)
	validator := clusterroletemplatebinding.NewValidator(crtbResolver, resolver, roleResolver, nil, clusterCache)
	type args struct {
		oldCRTB  func() *apisv3.ClusterRoleTemplateBinding
		newCRTB  func() *apisv3.ClusterRoleTemplateBinding
		username string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		allowed bool
	}{
		// base test user correctly binding a different user to a roleTemplate {PASS}.
		{
			name: "base test valid privileges",
			args: args{
				username: adminUser,
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = testUser
					baseCRTB.RoleTemplateName = c.adminRT.Name
					return baseCRTB
				},
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding { return nil },
			},
			allowed: true,
		},

		// Users privileges evaluated via CRTB {PASS}.
		{
			name: "crtb check test",
			args: args{
				username: crtbUser,
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = testUser
					baseCRTB.RoleTemplateName = c.adminRT.Name
					return baseCRTB
				},
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding { return nil },
			},
			allowed: true,
		},

		// Users attempting to privilege escalate another user get denied {FAIL}.
		{
			name: "privilege escalation other user",
			args: args{
				username: testUser,
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = crtbUser
					baseCRTB.RoleTemplateName = c.adminRT.Name
					return baseCRTB
				},
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding { return nil },
			},
			allowed: false,
		},

		// Users attempting to privilege escalate themselves  {FAIL}.
		{
			name: "privilege escalation self",
			args: args{
				username: testUser,
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = testUser
					baseCRTB.RoleTemplateName = c.adminRT.Name
					return baseCRTB
				},
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding { return nil },
			},
			allowed: false,
		},

		// Test that user can still be admitted with failed auth check {PASS}.
		{
			name: "failed escalate verb check",
			args: args{
				username: errorUser,
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = testUser
					baseCRTB.RoleTemplateName = c.adminRT.Name
					return baseCRTB
				},
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding { return nil },
			},
			allowed: true,
		},
	}

	for i := range tests {
		test := tests[i]
		c.Run(test.name, func() {
			req := createCRTBRequest(c.T(), test.args.oldCRTB(), test.args.newCRTB(), test.args.username)
			admitters := validator.Admitters()
			assert.Len(c.T(), admitters, 1)
			resp, err := admitters[0].Admit(req)
			c.NoError(err, "Admit failed")
			if resp.Allowed != test.allowed {
				c.Failf("Response was incorrectly validated", "Wanted response.Allowed = '%v' got %v: result=%+v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

func (c *ClusterRoleTemplateBindingSuite) Test_UpdateValidation() {
	const (
		adminUser    = "admin-userid"
		newUser      = "newUser-userid"
		newUserPrinc = "local://newUser"
		testGroup    = "testGroup"
	)
	clusterRoles := []*rbacv1.ClusterRole{c.adminCR}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: c.adminCR.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)

	ctrl := gomock.NewController(c.T())
	roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
	roleTemplateCache.EXPECT().Get(c.adminRT.Name).Return(c.adminRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().List(gomock.Any()).Return([]*apisv3.RoleTemplate{c.adminRT}, nil).AnyTimes()
	clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	crtbCache := fake.NewMockCacheInterface[*apisv3.ClusterRoleTemplateBinding](ctrl)
	crtbCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any())
	crtbCache.EXPECT().GetByIndex(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	clusterCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.Cluster](ctrl)
	clusterCache.EXPECT().Get(defaultClusterID).Return(&apisv3.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: defaultClusterID,
		},
	}, nil).AnyTimes()

	crtbResolver := resolvers.NewCRTBRuleResolver(crtbCache, roleResolver)
	validator := clusterroletemplatebinding.NewValidator(crtbResolver, resolver, roleResolver, nil, clusterCache)
	type args struct {
		oldCRTB  func() *apisv3.ClusterRoleTemplateBinding
		newCRTB  func() *apisv3.ClusterRoleTemplateBinding
		username string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		allowed bool
	}{
		{
			name: "base test valid CRTB update",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.Name = "oldName"
					baseCRTB.Labels[grbOwnerLabel] = "some-grb"
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.Name = "newName"
					baseCRTB.Labels[grbOwnerLabel] = "some-grb"
					return baseCRTB
				},
			},
			allowed: true,
		},
		{
			name: "update RoleTemplate",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.RoleTemplateName = c.readNodesRT.Name
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "update previously set user",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = "testuser1"
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = newUser
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "update previously unset user",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = ""
					baseCRTB.UserPrincipalName = newUserPrinc
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = newUser
					baseCRTB.UserPrincipalName = newUserPrinc
					return baseCRTB
				},
			},
			allowed: true,
		},
		{
			name: "update previously unset user and set group ",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = ""
					baseCRTB.GroupName = testGroup
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = newUser
					baseCRTB.GroupName = testGroup
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "update previously set user principal",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserPrincipalName = "local://testuser1"
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserPrincipalName = newUserPrinc
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "update previously unset user principal",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = newUser
					baseCRTB.UserPrincipalName = ""
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = newUser
					baseCRTB.UserPrincipalName = newUserPrinc
					return baseCRTB
				},
			},
			allowed: true,
		},
		{
			name: "update previously set group",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = ""
					baseCRTB.GroupName = testGroup
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = ""
					baseCRTB.GroupName = ""
					return baseCRTB
				},
			},
			allowed: false,
		},

		{
			name: "update previously unset group",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = ""
					baseCRTB.GroupName = ""
					baseCRTB.GroupPrincipalName = "local://testgroup"
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = ""
					baseCRTB.GroupName = testGroup
					baseCRTB.GroupPrincipalName = "local://testgroup"
					return baseCRTB
				},
			},
			allowed: true,
		},
		{
			name: "update previously unset group",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = "testuser"
					baseCRTB.GroupName = ""
					baseCRTB.GroupPrincipalName = ""
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = "testuser"
					baseCRTB.GroupName = testGroup
					baseCRTB.GroupPrincipalName = ""
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "update previously set group principal",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = ""
					baseCRTB.GroupPrincipalName = "local://testuser1"
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = ""
					baseCRTB.GroupPrincipalName = newUserPrinc
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "update previously unset group principal",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = ""
					baseCRTB.GroupName = testGroup
					baseCRTB.GroupPrincipalName = ""
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = ""
					baseCRTB.GroupName = testGroup
					baseCRTB.UserPrincipalName = "local://newGroup"
					return baseCRTB
				},
			},
			allowed: true,
		},
		{
			name: "update clusterName",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.ClusterName = "testCluster"
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.ClusterName = "newCluster"
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "update grbOwnerLabel",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.Labels[grbOwnerLabel] = "some-grb"
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.Labels[grbOwnerLabel] = "some-other-grb"
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "update previously unset grbOwnerLabel",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.Labels[grbOwnerLabel] = "some-new-grb"
					return baseCRTB
				},
			},
			allowed: false,
		},
	}

	for i := range tests {
		test := tests[i]
		c.Run(test.name, func() {
			c.T().Parallel()
			req := createCRTBRequest(c.T(), test.args.oldCRTB(), test.args.newCRTB(), test.args.username)
			admitters := validator.Admitters()
			assert.Len(c.T(), admitters, 1)
			resp, err := admitters[0].Admit(req)
			c.NoError(err, "Admit failed")
			if resp.Allowed != test.allowed {
				c.Failf("Response was incorrectly validated", "Wanted response.Allowed = '%v' got %v: result=%+v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

func (c *ClusterRoleTemplateBindingSuite) Test_Create() {
	type testState struct {
		clusterRoleCacheMock *fake.MockNonNamespacedCacheInterface[*rbacv1.ClusterRole]
	}
	ctrl := gomock.NewController(c.T())
	const adminUser = "admin-userid"
	const writeNodeUser = "write-node-userid"
	const readPodUser = "read-pod-userid"
	const badRoleTemplateName = "bad-roletemplate"
	const missingCluster = "missing-cluster"
	const errorCluster = "error-cluster"
	const nilCluster = "nil-cluster"
	clusterRoles := []*rbacv1.ClusterRole{c.adminCR, c.writeNodeCR, c.readPodsCR}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: c.adminCR.Name},
		},
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: writeNodeUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: c.writeNodeCR.Name},
		},
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: readPodUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: c.readPodsCR.Name},
		},
	}

	validGRB := v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "valid-grb",
		},
		UserName:       adminUser,
		GlobalRoleName: "some-gr",
	}
	deletingGRB := v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:              "deleting-grb",
			DeletionTimestamp: &metav1.Time{Time: time.Now()},
		},
		UserName:       adminUser,
		GlobalRoleName: "some-gr",
	}

	validatorWithMocks := func(state testState) *clusterroletemplatebinding.Validator {
		resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)
		roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
		roleTemplateCache.EXPECT().Get(c.adminRT.Name).Return(c.adminRT, nil).AnyTimes()
		roleTemplateCache.EXPECT().Get(c.externalRulesWriteNodesRT.Name).Return(c.externalRulesWriteNodesRT, nil).AnyTimes()
		roleTemplateCache.EXPECT().Get(c.externalClusterRoleRT.Name).Return(c.externalClusterRoleRT, nil).AnyTimes()
		roleTemplateCache.EXPECT().Get(c.lockedRT.Name).Return(c.lockedRT, nil).AnyTimes()
		roleTemplateCache.EXPECT().Get(c.projectRT.Name).Return(c.projectRT, nil).AnyTimes()
		expectedError := apierrors.NewNotFound(schema.GroupResource{}, "")
		roleTemplateCache.EXPECT().Get(badRoleTemplateName).Return(nil, expectedError).AnyTimes()
		roleTemplateCache.EXPECT().Get("").Return(nil, expectedError).AnyTimes()
		roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, state.clusterRoleCacheMock)
		crtbCache := fake.NewMockCacheInterface[*apisv3.ClusterRoleTemplateBinding](ctrl)
		crtbCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any())
		crtbCache.EXPECT().GetByIndex(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
		grbCache := fake.NewMockNonNamespacedCacheInterface[*v3.GlobalRoleBinding](ctrl)
		notFoundError := apierrors.NewNotFound(schema.GroupResource{
			Group:    "management.cattle.io",
			Resource: "globalrolebindings",
		}, "not-found")
		grbCache.EXPECT().Get(validGRB.Name).Return(&validGRB, nil).AnyTimes()
		grbCache.EXPECT().Get(deletingGRB.Name).Return(&deletingGRB, nil).AnyTimes()
		grbCache.EXPECT().Get("error").Return(nil, fmt.Errorf("server not available")).AnyTimes()
		grbCache.EXPECT().Get("not-found").Return(nil, notFoundError).AnyTimes()
		grbCache.EXPECT().Get("nil-grb").Return(nil, nil).AnyTimes()

		clusterCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.Cluster](ctrl)
		clusterCache.EXPECT().Get(defaultClusterID).Return(&apisv3.Cluster{
			ObjectMeta: metav1.ObjectMeta{
				Name: defaultClusterID,
			},
		}, nil).AnyTimes()
		clusterCache.EXPECT().Get(errorCluster).Return(nil, fmt.Errorf("server not available")).AnyTimes()
		clusterCache.EXPECT().Get(missingCluster).Return(nil, apierrors.NewNotFound(schema.GroupResource{
			Group:    "management.cattle.io",
			Resource: "clusters",
		}, missingCluster)).AnyTimes()
		clusterCache.EXPECT().Get(nilCluster).Return(nil, nil).AnyTimes()

		crtbResolver := resolvers.NewCRTBRuleResolver(crtbCache, roleResolver)
		return clusterroletemplatebinding.NewValidator(crtbResolver, resolver, roleResolver, grbCache, clusterCache)
	}
	type args struct {
		oldCRTB  func() *apisv3.ClusterRoleTemplateBinding
		newCRTB  func() *apisv3.ClusterRoleTemplateBinding
		username string
	}
	tests := []struct {
		name       string
		args       args
		wantErr    bool
		allowed    bool
		stateSetup func(state testState)
	}{
		{
			name: "base test valid CRTB",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					return baseCRTB
				},
			},
			allowed: true,
		},
		{
			name: "missing cluster name",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.ClusterName = ""
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "missing role template",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.RoleTemplateName = ""
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "missing user and group",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = ""
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "both user and group set",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.UserName = "newUser"
					baseCRTB.GroupName = "newGroup"
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "bad role template name",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.RoleTemplateName = badRoleTemplateName
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "role template with wrong context",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.RoleTemplateName = c.projectRT.Name
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "locked role template",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.RoleTemplateName = c.lockedRT.Name
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "locked role template, crtb owned by grb",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.RoleTemplateName = c.lockedRT.Name
					baseCRTB.Labels[grbOwnerLabel] = validGRB.Name
					return baseCRTB
				},
			},
			allowed: true,
		},
		{
			name: "locked role template, crtb owned by deleting grb",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.RoleTemplateName = c.lockedRT.Name
					baseCRTB.Labels[grbOwnerLabel] = deletingGRB.Name
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "locked role template, crtb owned by nil grb",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.RoleTemplateName = c.lockedRT.Name
					baseCRTB.Labels[grbOwnerLabel] = "nil-grb"
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "locked role template, crtb owned by missing grb",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.RoleTemplateName = c.lockedRT.Name
					baseCRTB.Labels[grbOwnerLabel] = "not-found"
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "locked role template, crtb owned by error grb",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.RoleTemplateName = c.lockedRT.Name
					baseCRTB.Labels[grbOwnerLabel] = "error"
					return baseCRTB
				},
			},
			wantErr: true,
		},
		{
			name: "create mismatched clusterName and namespace",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.ClusterName = "c-mismatch"
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "create missing cluster name",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.Namespace = missingCluster
					baseCRTB.ClusterName = missingCluster
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "create error cluster",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.Namespace = errorCluster
					baseCRTB.ClusterName = errorCluster
					return baseCRTB
				},
			},
			allowed: false,
			wantErr: true,
		},
		{
			name: "create nil cluster",
			args: args{
				username: adminUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.Namespace = nilCluster
					baseCRTB.ClusterName = nilCluster
					return baseCRTB
				},
			},
			allowed: false,
		},
		{
			name: "external RT with externalRules valid CRTB creation",
			args: args{
				username: writeNodeUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.RoleTemplateName = "external-rule-write-nodes"

					return baseCRTB
				},
			},
			allowed: true,
		},
		{
			name: "external RT with externalRules rejected when there are not enough permissions",
			args: args{
				username: readPodUser,
				oldCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					return nil
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.RoleTemplateName = "external-rule-write-nodes"

					return baseCRTB
				},
			},
			allowed: false,
		},
	}

	for i := range tests {
		test := tests[i]
		c.Run(test.name, func() {
			c.T().Parallel()
			req := createCRTBRequest(c.T(), test.args.oldCRTB(), test.args.newCRTB(), test.args.username)
			clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
			state := testState{
				clusterRoleCacheMock: clusterRoleCache,
			}
			if test.stateSetup != nil {
				test.stateSetup(state)
			}
			validator := validatorWithMocks(state)
			admitters := validator.Admitters()
			assert.Len(c.T(), admitters, 1)
			resp, err := admitters[0].Admit(req)
			if test.wantErr {
				c.Error(err)
			} else {
				c.NoError(err, "Admit failed")
				if resp.Allowed != test.allowed {
					c.Failf("Response was incorrectly validated", "Wanted response.Allowed = '%v' got '%v': result=%+v", test.name, test.allowed, resp.Allowed, resp.Result)
				}
			}
		})
	}
}

// createCRTBRequest will return a new webhookRequest with the using the given CRTBs
// if oldCRTB is nil then a request will be returned as a create operation.
// else the request will look like and update operation.
func createCRTBRequest(t *testing.T, oldCRTB, newCRTB *apisv3.ClusterRoleTemplateBinding, username string) *admission.Request {
	t.Helper()
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "ClusterRoleTemplateBinding"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "clusterroletemplatebindings"}
	req := &admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Name:            newCRTB.Name,
			Namespace:       newCRTB.Namespace,
			Operation:       v1.Create,
			UserInfo:        v1authentication.UserInfo{Username: username, UID: ""},
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
		Context: context.Background(),
	}
	var err error
	req.Object.Raw, err = json.Marshal(newCRTB)
	assert.NoError(t, err, "Failed to marshal CRTB while creating request")
	if oldCRTB != nil {
		req.Operation = v1.Update
		req.OldObject.Raw, err = json.Marshal(oldCRTB)
		assert.NoError(t, err, "Failed to marshal CRTB while creating request")
	}
	return req
}

func newDefaultCRTB() *apisv3.ClusterRoleTemplateBinding {
	return &apisv3.ClusterRoleTemplateBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ClusterRoleTemplateBinding", APIVersion: "management.cattle.io/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "crtb-new",
			GenerateName:      "crtb-",
			Namespace:         defaultClusterID,
			SelfLink:          "",
			UID:               "6534e4ef-f07b-4c61-b88d-95a92cce4852",
			ResourceVersion:   "1",
			Generation:        1,
			CreationTimestamp: metav1.Time{},
			ManagedFields:     []metav1.ManagedFieldsEntry{},
			Labels:            map[string]string{},
		},
		UserName:         "user1",
		ClusterName:      defaultClusterID,
		RoleTemplateName: "admin-role",
	}
}
