package clusterroletemplatebinding_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/fakes"
	"github.com/rancher/webhook/pkg/resources/validation/clusterroletemplatebinding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	v1authentication "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

var errExpected = errors.New("expected test error")

type ClusterRoleTemplateBindingSuite struct {
	suite.Suite
	adminRT         *apisv3.RoleTemplate
	readNodesRT     *apisv3.RoleTemplate
	lockedRT        *apisv3.RoleTemplate
	adminCR         *rbacv1.ClusterRole
	writeNodeCR     *rbacv1.ClusterRole
	readServiceRole *rbacv1.Role
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
	c.lockedRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "locked-role",
		},
		DisplayName: "Locked Role",
		Rules:       []rbacv1.PolicyRule{ruleReadServices},
		Locked:      true,
		Context:     "cluster",
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
	roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
	roleTemplateCache.EXPECT().Get(c.adminRT.Name).Return(c.adminRT, nil).AnyTimes()
	clusterRoleCache := fakes.NewMockClusterRoleCache(ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	crtbCache := fakes.NewMockClusterRoleTemplateBindingCache(ctrl)
	crtbCache.EXPECT().List(newDefaultCRTB().ClusterName, gomock.Any()).Return([]*apisv3.ClusterRoleTemplateBinding{
		{
			UserName:         crtbUser,
			RoleTemplateName: c.adminRT.Name,
		},
	}, nil).AnyTimes()
	validator := clusterroletemplatebinding.NewValidator(crtbCache, resolver,
		roleResolver,
	)
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
			resp, err := validator.Admit(req)
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
	roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
	roleTemplateCache.EXPECT().Get(c.adminRT.Name).Return(c.adminRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().List(gomock.Any()).Return([]*apisv3.RoleTemplate{c.adminRT}, nil).AnyTimes()
	clusterRoleCache := fakes.NewMockClusterRoleCache(ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	crtbCache := fakes.NewMockClusterRoleTemplateBindingCache(ctrl)
	crtbCache.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	validator := clusterroletemplatebinding.NewValidator(crtbCache, resolver,
		roleResolver,
	)
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
					return baseCRTB
				},
				newCRTB: func() *apisv3.ClusterRoleTemplateBinding {
					baseCRTB := newDefaultCRTB()
					baseCRTB.Name = "newName"
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
	}

	for i := range tests {
		test := tests[i]
		c.Run(test.name, func() {
			c.T().Parallel()
			req := createCRTBRequest(c.T(), test.args.oldCRTB(), test.args.newCRTB(), test.args.username)
			resp, err := validator.Admit(req)
			c.NoError(err, "Admit failed")
			if resp.Allowed != test.allowed {
				c.Failf("Response was incorrectly validated", "Wanted response.Allowed = '%v' got %v: result=%+v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

func (c *ClusterRoleTemplateBindingSuite) Test_Create() {
	const adminUser = "admin-userid"
	const badRoleTemplateName = "bad-roletemplate"
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
	roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
	roleTemplateCache.EXPECT().Get(c.adminRT.Name).Return(c.adminRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(c.lockedRT.Name).Return(c.lockedRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(badRoleTemplateName).Return(nil, errExpected).AnyTimes()
	roleTemplateCache.EXPECT().Get("").Return(nil, errExpected).AnyTimes()
	clusterRoleCache := fakes.NewMockClusterRoleCache(ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	crtbCache := fakes.NewMockClusterRoleTemplateBindingCache(ctrl)
	crtbCache.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	validator := clusterroletemplatebinding.NewValidator(crtbCache, resolver,
		roleResolver,
	)
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
			name: "missing roleTemplate",
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
			name: "both user and group set",
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
			name: "Locked roleTemplate",
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
	}

	for i := range tests {
		test := tests[i]
		c.Run(test.name, func() {
			c.T().Parallel()
			req := createCRTBRequest(c.T(), test.args.oldCRTB(), test.args.newCRTB(), test.args.username)
			resp, err := validator.Admit(req)
			c.NoError(err, "Admit failed")
			if resp.Allowed != test.allowed {
				c.Failf("Response was incorrectly validated", "Wanted response.Allowed = '%v' got %v: result=%+v", test.allowed, resp.Allowed, resp.Result)
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
			Namespace:         "c-namespace",
			SelfLink:          "",
			UID:               "6534e4ef-f07b-4c61-b88d-95a92cce4852",
			ResourceVersion:   "1",
			Generation:        1,
			CreationTimestamp: metav1.Time{},
			ManagedFields:     []metav1.ManagedFieldsEntry{},
		},
		UserName:         "user1",
		ClusterName:      "c-namespace",
		RoleTemplateName: "admin-role",
	}
}
