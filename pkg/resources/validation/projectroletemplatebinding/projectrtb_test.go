package projectroletemplatebinding_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/fakes"
	"github.com/rancher/webhook/pkg/resources/validation/projectroletemplatebinding"
	"github.com/rancher/wrangler/pkg/webhook"
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

const (
	clusterID = "cluster-id"
	projectID = "project-id"
)

type ProjectRoleTemplateBindingSuite struct {
	suite.Suite
	adminRT         *apisv3.RoleTemplate
	readNodesRT     *apisv3.RoleTemplate
	lockedRT        *apisv3.RoleTemplate
	adminCR         *rbacv1.ClusterRole
	writeNodeCR     *rbacv1.ClusterRole
	readServiceRole *rbacv1.Role
}

func TestProjectRoleTemplateBindings(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(ProjectRoleTemplateBindingSuite))
}

func (p *ProjectRoleTemplateBindingSuite) SetupSuite() {
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
	p.readNodesRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "read-role",
		},
		DisplayName: "Read Role",
		Rules:       []rbacv1.PolicyRule{ruleReadPods, ruleWriteNodes},
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
	p.lockedRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "locked-role",
		},
		DisplayName: "Locked Role",
		Rules:       []rbacv1.PolicyRule{ruleReadServices},
		Locked:      true,
		Context:     "project",
	}
	p.adminCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "admin-role",
		},
		Rules: []rbacv1.PolicyRule{ruleAdmin},
	}
	p.writeNodeCR = &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "write-role"},
		Rules:      []rbacv1.PolicyRule{ruleWriteNodes, ruleWriteNodes},
	}
	p.readServiceRole = &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Namespace: "namespace1", Name: "read-service"},
		Rules:      []rbacv1.PolicyRule{ruleReadServices},
	}
}

func (p *ProjectRoleTemplateBindingSuite) Test_PrivilegeEscalation() {
	const adminUser = "admin-userid"
	const testUser = "test-userid"
	const errorUser = "error-userid"
	const prtbUser = "prtb-userid"
	const crtbUser = "crtb-userid"
	roles := []*rbacv1.Role{p.readServiceRole}
	clusterRoles := []*rbacv1.ClusterRole{p.adminCR, p.writeNodeCR}
	roleBindings := []*rbacv1.RoleBinding{
		{
			ObjectMeta: metav1.ObjectMeta{Namespace: p.readServiceRole.Namespace},
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: testUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: p.readServiceRole.Name},
		},
	}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
				{Kind: rbacv1.UserKind, Name: errorUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: p.adminCR.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(roles, roleBindings, clusterRoles, clusterRoleBindings)

	ctrl := gomock.NewController(p.T())
	roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
	roleTemplateCache.EXPECT().Get(p.adminRT.Name).Return(p.adminRT, nil).AnyTimes()
	clusterRoleCache := fakes.NewMockClusterRoleCache(ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	prtbCache := fakes.NewMockProjectRoleTemplateBindingCache(ctrl)
	prtbCache.EXPECT().List(projectID, gomock.Any()).Return([]*apisv3.ProjectRoleTemplateBinding{
		{
			UserName:         prtbUser,
			RoleTemplateName: p.adminRT.Name,
		},
	}, nil).AnyTimes()
	crtbCache := fakes.NewMockClusterRoleTemplateBindingCache(ctrl)
	crtbCache.EXPECT().List(clusterID, gomock.Any()).Return([]*apisv3.ClusterRoleTemplateBinding{
		{
			UserName:         crtbUser,
			RoleTemplateName: p.adminRT.Name,
		},
	}, nil).AnyTimes()
	validator := projectroletemplatebinding.NewValidator(prtbCache, crtbCache, resolver,
		roleResolver,
	)
	type args struct {
		oldPRTB  func() *apisv3.ProjectRoleTemplateBinding
		newPRTB  func() *apisv3.ProjectRoleTemplateBinding
		username string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		allowed bool
	}{
		// base test admin correctly binding a different user to a roleTemplate {PASS}.
		{
			name: "base test valid privileges",
			args: args{
				username: adminUser,
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = testUser
					basePRTB.RoleTemplateName = p.adminRT.Name
					return basePRTB
				},
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding { return nil },
			},
			allowed: true,
		},

		// Users privileges are stored in a crtb {PASS}.
		{
			name: "CRTB resolver test",
			args: args{
				username: crtbUser,
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = testUser
					basePRTB.RoleTemplateName = p.adminRT.Name
					return basePRTB
				},
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding { return nil },
			},
			allowed: true,
		},

		// Users privileges are stored in a crtb {PASS}.
		{
			name: "PRTB resolver test",
			args: args{
				username: prtbUser,
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = testUser
					basePRTB.RoleTemplateName = p.adminRT.Name
					return basePRTB
				},
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding { return nil },
			},
			allowed: true,
		},

		// Users attempting to privilege escalate another user get denied {FAIL}.
		{
			name: "privilege escalation other user",
			args: args{
				username: testUser,
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = errorUser
					basePRTB.RoleTemplateName = p.adminRT.Name
					return basePRTB
				},
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding { return nil },
			},
			allowed: false,
		},

		// Users attempting to privilege escalate themselves  {FAIL}.
		{
			name: "privilege escalation self",
			args: args{
				username: testUser,
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = testUser
					basePRTB.RoleTemplateName = p.adminRT.Name
					return basePRTB
				},
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding { return nil },
			},
			allowed: false,
		},

		// Test that user can still be admitted with failed auth check {PASS}.
		{
			name: "failed escalate verb check",
			args: args{
				username: errorUser,
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = testUser
					basePRTB.RoleTemplateName = p.adminRT.Name
					return basePRTB
				},
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding { return nil },
			},
			allowed: true,
		},
	}

	for i := range tests {
		test := tests[i]
		p.Run(test.name, func() {
			p.T().Parallel()
			resp, req := createPRTBRequestAndResponse(p.T(), test.args.oldPRTB(), test.args.newPRTB(), test.args.username)
			err := validator.Admit(resp, req)
			p.NoError(err, "Admit failed")
			if resp.Allowed != test.allowed {
				p.Failf("Response was incorrectly validated", "Wanted response.Allowed = '%v' got %v: result=%+v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

func (p *ProjectRoleTemplateBindingSuite) Test_UpdateValidation() {
	const (
		adminUser    = "admin-userid"
		newUser      = "newUser-userid"
		newUserPrinc = "local://newUser"
		testGroup    = "testGroup"
	)
	clusterRoles := []*rbacv1.ClusterRole{p.adminCR}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: p.adminCR.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)

	ctrl := gomock.NewController(p.T())
	roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
	roleTemplateCache.EXPECT().Get(p.adminRT.Name).Return(p.adminRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().List(gomock.Any()).Return([]*apisv3.RoleTemplate{p.adminRT}, nil).AnyTimes()
	clusterRoleCache := fakes.NewMockClusterRoleCache(ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	prtbCache := fakes.NewMockProjectRoleTemplateBindingCache(ctrl)
	prtbCache.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	crtbCache := fakes.NewMockClusterRoleTemplateBindingCache(ctrl)
	crtbCache.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	validator := projectroletemplatebinding.NewValidator(prtbCache, crtbCache, resolver, roleResolver)
	type args struct {
		oldPRTB  func() *apisv3.ProjectRoleTemplateBinding
		newPRTB  func() *apisv3.ProjectRoleTemplateBinding
		username string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		allowed bool
	}{
		{
			name: "base test valid PRTB update",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.Name = "oldName"
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.Name = "newName"
					return basePRTB
				},
			},
			allowed: true,
		},
		{
			name: "update RoleTemplate",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.RoleTemplateName = p.readNodesRT.Name
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "update previously set user",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = "testuser1"
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = newUser
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "update previously unset user",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					basePRTB.UserPrincipalName = newUserPrinc
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = newUser
					basePRTB.UserPrincipalName = newUserPrinc
					return basePRTB
				},
			},
			allowed: true,
		},
		{
			name: "update previously unset user and set group ",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					basePRTB.GroupName = testGroup
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = newUser
					basePRTB.GroupName = testGroup
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "update previously set user principal",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserPrincipalName = "local://testuser1"
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserPrincipalName = newUserPrinc
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "update previously unset user principal",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = newUser
					basePRTB.UserPrincipalName = ""
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = newUser
					basePRTB.UserPrincipalName = newUserPrinc
					return basePRTB
				},
			},
			allowed: true,
		},
		{
			name: "update previously set group",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					basePRTB.GroupName = testGroup
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					basePRTB.GroupName = ""
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "update previously unset group",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					basePRTB.GroupName = ""
					basePRTB.GroupPrincipalName = "local://testgroup"
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					basePRTB.GroupName = testGroup
					basePRTB.GroupPrincipalName = "local://testgroup"
					return basePRTB
				},
			},
			allowed: true,
		},
		{
			name: "update previously unset group",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = "testuser"
					basePRTB.GroupName = ""
					basePRTB.GroupPrincipalName = ""
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = "testuser"
					basePRTB.GroupName = testGroup
					basePRTB.GroupPrincipalName = ""
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "update previously set group principal",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					basePRTB.GroupPrincipalName = "local://testuser1"
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					basePRTB.GroupPrincipalName = newUserPrinc
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "update previously unset group principal",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					basePRTB.GroupName = testGroup
					basePRTB.GroupPrincipalName = ""
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					basePRTB.GroupName = testGroup
					basePRTB.UserPrincipalName = "local://newGroup"
					return basePRTB
				},
			},
			allowed: true,
		},
	}

	for i := range tests {
		test := tests[i]
		p.Run(test.name, func() {
			p.T().Parallel()
			resp, req := createPRTBRequestAndResponse(p.T(), test.args.oldPRTB(), test.args.newPRTB(), test.args.username)
			err := validator.Admit(resp, req)
			p.NoError(err, "Admit failed")
			if resp.Allowed != test.allowed {
				p.Failf("Response was incorrectly validated", "Wanted response.Allowed = '%v' got %v: result=%+v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

func (p *ProjectRoleTemplateBindingSuite) Test_Create() {
	const adminUser = "admin-userid"
	const badRoleTemplateName = "bad-roletemplate"
	clusterRoles := []*rbacv1.ClusterRole{p.adminCR}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: p.adminCR.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)

	ctrl := gomock.NewController(p.T())
	roleTemplateCache := fakes.NewMockRoleTemplateCache(ctrl)
	roleTemplateCache.EXPECT().Get(p.adminRT.Name).Return(p.adminRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(p.lockedRT.Name).Return(p.lockedRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(badRoleTemplateName).Return(nil, errExpected).AnyTimes()
	roleTemplateCache.EXPECT().Get("").Return(nil, errExpected).AnyTimes()
	clusterRoleCache := fakes.NewMockClusterRoleCache(ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	prtbCache := fakes.NewMockProjectRoleTemplateBindingCache(ctrl)
	prtbCache.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	crtbCache := fakes.NewMockClusterRoleTemplateBindingCache(ctrl)
	crtbCache.EXPECT().List(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	validator := projectroletemplatebinding.NewValidator(prtbCache, crtbCache, resolver, roleResolver)

	type args struct {
		oldPRTB  func() *apisv3.ProjectRoleTemplateBinding
		newPRTB  func() *apisv3.ProjectRoleTemplateBinding
		username string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		allowed bool
	}{
		{
			name: "base test valid PRTB creation",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					return basePRTB
				},
			},
			allowed: true,
		},
		{
			name: "missing roleTemplate",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.RoleTemplateName = ""
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "missing user and group",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "both user and group set",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = "newUser"
					basePRTB.GroupName = "newGroup"
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "both user and group set",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.RoleTemplateName = badRoleTemplateName
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "Locked roleTemplate",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.RoleTemplateName = p.lockedRT.Name
					return basePRTB
				},
			},
			allowed: false,
		},
	}

	for i := range tests {
		test := tests[i]
		p.Run(test.name, func() {
			p.T().Parallel()
			resp, req := createPRTBRequestAndResponse(p.T(), test.args.oldPRTB(), test.args.newPRTB(), test.args.username)
			err := validator.Admit(resp, req)
			p.NoError(err, "Admit failed")
			if resp.Allowed != test.allowed {
				p.Failf("Response was incorrectly validated", "Wanted response.Allowed = '%v' got %v: result=%+v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

// createPRTBRequest will return a new webhookRequest with the using the given PRTBs
// if oldPRTB is nil then a request will be returned as a create operation.
// else the request will look like ana update operation.
func createPRTBRequestAndResponse(t *testing.T, oldPRTB, newPRTB *apisv3.ProjectRoleTemplateBinding, username string) (*webhook.Response, *webhook.Request) {
	t.Helper()
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "ProjectRoleTemplateBinding"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "projectroletemplatebindings"}
	req := &webhook.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Name:            newPRTB.Name,
			Namespace:       newPRTB.Namespace,
			Operation:       v1.Create,
			UserInfo:        v1authentication.UserInfo{Username: username, UID: ""},
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
		Context:     context.Background(),
		ObjTemplate: &apisv3.ProjectRoleTemplateBinding{},
	}
	var err error
	req.Object.Raw, err = json.Marshal(newPRTB)
	assert.NoError(t, err, "Failed to marshal PRTB while creating request")
	if oldPRTB != nil {
		req.Operation = v1.Update
		req.OldObject.Raw, err = json.Marshal(oldPRTB)
		assert.NoError(t, err, "Failed to marshal PRTB while creating request")
	}
	resp := &webhook.Response{
		AdmissionResponse: v1.AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Result:  &metav1.Status{},
		},
	}
	return resp, req
}

func newBasePRTB() *apisv3.ProjectRoleTemplateBinding {
	return &apisv3.ProjectRoleTemplateBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ProjectRoleTemplateBinding", APIVersion: "management.cattle.io/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "PRTB-new",
			GenerateName:      "PRTB-",
			Namespace:         "p-namespace",
			SelfLink:          "",
			UID:               "6534e4ef-f07b-4c61-b88d-95a92cce4852",
			ResourceVersion:   "1",
			Generation:        1,
			CreationTimestamp: metav1.Time{},
			ManagedFields:     []metav1.ManagedFieldsEntry{},
		},
		UserName:         "user1",
		RoleTemplateName: "admin-role",
		ProjectName:      fmt.Sprintf("%s:%s", clusterID, projectID),
	}
}
