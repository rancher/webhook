package projectroletemplatebinding_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/resolvers"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/projectroletemplatebinding"
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

var errExpected = errors.New("expected test error")

const (
	clusterID = "cluster-id"
	projectID = "project-id"
)

type ProjectRoleTemplateBindingSuite struct {
	suite.Suite
	adminRT          *apisv3.RoleTemplate
	readNodesRT      *apisv3.RoleTemplate
	lockedRT         *apisv3.RoleTemplate
	clusterContextRT *apisv3.RoleTemplate
	adminCR          *rbacv1.ClusterRole
	writeNodeCR      *rbacv1.ClusterRole
	readServiceRole  *rbacv1.Role
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
	p.clusterContextRT = &apisv3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-member",
		},
		DisplayName: "Cluster Member",
		Rules:       []rbacv1.PolicyRule{ruleReadServices},
		Context:     "cluster",
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

func (p *ProjectRoleTemplateBindingSuite) TestPrivilegeEscalation() {
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
	roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
	roleTemplateCache.EXPECT().Get(p.adminRT.Name).Return(p.adminRT, nil).AnyTimes()
	clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	prtbCache := fake.NewMockCacheInterface[*apisv3.ProjectRoleTemplateBinding](ctrl)
	prtbCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any())
	prtbCache.EXPECT().GetByIndex(gomock.Any(), resolvers.GetUserKey(prtbUser, projectID)).Return([]*apisv3.ProjectRoleTemplateBinding{{
		UserName:         prtbUser,
		RoleTemplateName: p.adminRT.Name,
	},
	}, nil).AnyTimes()
	prtbCache.EXPECT().GetByIndex(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	crtbCache := fake.NewMockCacheInterface[*apisv3.ClusterRoleTemplateBinding](ctrl)
	crtbCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any())
	crtbCache.EXPECT().GetByIndex(gomock.Any(), resolvers.GetUserKey(crtbUser, clusterID)).Return([]*apisv3.ClusterRoleTemplateBinding{
		{
			UserName:         crtbUser,
			RoleTemplateName: p.adminRT.Name,
		},
	}, nil).AnyTimes()
	crtbCache.EXPECT().GetByIndex(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()

	crtbResolver := resolvers.NewCRTBRuleResolver(crtbCache, roleResolver)
	prtbResolver := resolvers.NewPRTBRuleResolver(prtbCache, roleResolver)

	clusterCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.Cluster](ctrl)
	clusterCache.EXPECT().Get(clusterID).Return(&apisv3.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterID,
		},
	}, nil).AnyTimes()

	projectCache := fake.NewMockCacheInterface[*apisv3.Project](ctrl)
	projectCache.EXPECT().Get(clusterID, projectID).Return(&apisv3.Project{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: clusterID,
			Name:      projectID,
		},
		Spec: apisv3.ProjectSpec{
			ClusterName: clusterID,
		},
	}, nil).AnyTimes()
	validator := projectroletemplatebinding.NewValidator(prtbResolver, crtbResolver, resolver, roleResolver, clusterCache, projectCache)
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
			req := createPRTBRequest(p.T(), test.args.oldPRTB(), test.args.newPRTB(), test.args.username)
			admitters := validator.Admitters()
			p.Len(admitters, 1)
			resp, err := admitters[0].Admit(req)
			p.NoError(err, "Admit failed")
			if resp.Allowed != test.allowed {
				p.Failf("Response was incorrectly validated", "Wanted response.Allowed = '%v' got %v: result=%+v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

func (p *ProjectRoleTemplateBindingSuite) TestValidationOnUpdate() {
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
	roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
	roleTemplateCache.EXPECT().Get(p.adminRT.Name).Return(p.adminRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().List(gomock.Any()).Return([]*apisv3.RoleTemplate{p.adminRT}, nil).AnyTimes()
	clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	prtbCache := fake.NewMockCacheInterface[*apisv3.ProjectRoleTemplateBinding](ctrl)
	prtbCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any())
	prtbCache.EXPECT().GetByIndex(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	crtbCache := fake.NewMockCacheInterface[*apisv3.ClusterRoleTemplateBinding](ctrl)
	crtbCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any())
	crtbCache.EXPECT().GetByIndex(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	crtbResolver := resolvers.NewCRTBRuleResolver(crtbCache, roleResolver)
	prtbResolver := resolvers.NewPRTBRuleResolver(prtbCache, roleResolver)
	clusterCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.Cluster](ctrl)
	clusterCache.EXPECT().Get(clusterID).Return(&apisv3.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterID,
		},
	}, nil).AnyTimes()

	projectCache := fake.NewMockCacheInterface[*apisv3.Project](ctrl)
	projectCache.EXPECT().Get(clusterID, projectID).Return(&apisv3.Project{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: clusterID,
			Name:      projectID,
		},
		Spec: apisv3.ProjectSpec{
			ClusterName: clusterID,
		},
	}, nil).AnyTimes()

	validator := projectroletemplatebinding.NewValidator(prtbResolver, crtbResolver, resolver, roleResolver, clusterCache, projectCache)
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
			name: "update role template",
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
			name: "update service account",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.ServiceAccount = "default"
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
			name: "update removing a previously set service account",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					basePRTB.ServiceAccount = "p1:default"
					return basePRTB
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
			name: "update previously set service account",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					basePRTB.ServiceAccount = "p1:default"
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					basePRTB.ServiceAccount = "p1:another"
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "set a previously unset service account with a user name already present",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.ServiceAccount = "p1:another"
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
			name: "update previously unset user and set group",
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
			name: "update previously unset group with no previously set user",
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
			name: "update previously unset user principal",
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
		{
			name: "update previously set project name",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					return basePRTB
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.ProjectName = "newName"
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
			req := createPRTBRequest(p.T(), test.args.oldPRTB(), test.args.newPRTB(), test.args.username)
			admitters := validator.Admitters()
			p.Len(admitters, 1)
			resp, err := admitters[0].Admit(req)
			p.NoError(err, "Admit failed")
			if resp.Allowed != test.allowed {
				p.Failf("Response was incorrectly validated", "Wanted response.Allowed = '%v' got %v: result=%+v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

func (p *ProjectRoleTemplateBindingSuite) TestValidationOnCreate() {
	const adminUser = "admin-userid"
	const badRoleTemplateName = "bad-roletemplate"
	const missingCluster = "missing-cluster"
	const nilCluster = "nil-cluster"
	const errCluster = "error-cluster"
	const missingProject = "missing-project"
	const nilProject = "nil-project"
	const errProject = "error-project"
	const badSpecProject = "bad-spec"
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
	roleTemplateCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.RoleTemplate](ctrl)
	roleTemplateCache.EXPECT().Get(p.adminRT.Name).Return(p.adminRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(p.lockedRT.Name).Return(p.lockedRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(p.clusterContextRT.Name).Return(p.clusterContextRT, nil).AnyTimes()
	roleTemplateCache.EXPECT().Get(badRoleTemplateName).Return(nil, errExpected).AnyTimes()
	roleTemplateCache.EXPECT().Get("").Return(nil, errExpected).AnyTimes()
	clusterRoleCache := fake.NewMockNonNamespacedCacheInterface[*rbacv1.ClusterRole](ctrl)
	roleResolver := auth.NewRoleTemplateResolver(roleTemplateCache, clusterRoleCache)
	prtbCache := fake.NewMockCacheInterface[*apisv3.ProjectRoleTemplateBinding](ctrl)
	prtbCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any())
	prtbCache.EXPECT().GetByIndex(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	crtbCache := fake.NewMockCacheInterface[*apisv3.ClusterRoleTemplateBinding](ctrl)
	crtbCache.EXPECT().AddIndexer(gomock.Any(), gomock.Any())
	crtbCache.EXPECT().GetByIndex(gomock.Any(), gomock.Any()).Return(nil, nil).AnyTimes()
	crtbResolver := resolvers.NewCRTBRuleResolver(crtbCache, roleResolver)
	prtbResolver := resolvers.NewPRTBRuleResolver(prtbCache, roleResolver)

	clusterCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.Cluster](ctrl)
	clusterCache.EXPECT().Get(clusterID).Return(&apisv3.Cluster{
		ObjectMeta: metav1.ObjectMeta{
			Name: clusterID,
		},
	}, nil).AnyTimes()
	clusterCache.EXPECT().Get(nilCluster).Return(nil, nil).AnyTimes()
	clusterCache.EXPECT().Get(errCluster).Return(nil, fmt.Errorf("server not available")).AnyTimes()
	clusterCache.EXPECT().Get(missingCluster).Return(nil, apierrors.NewNotFound(schema.GroupResource{
		Group:    "management.cattle.io",
		Resource: "clusters",
	}, missingCluster)).AnyTimes()

	projectCache := fake.NewMockCacheInterface[*apisv3.Project](ctrl)
	projectCache.EXPECT().Get(clusterID, projectID).Return(&apisv3.Project{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: clusterID,
			Name:      projectID,
		},
		Spec: apisv3.ProjectSpec{
			ClusterName: clusterID,
		},
	}, nil).AnyTimes()
	projectCache.EXPECT().Get(clusterID, nilProject).Return(nil, nil).AnyTimes()
	projectCache.EXPECT().Get(clusterID, errProject).Return(nil, fmt.Errorf("server not available")).AnyTimes()
	projectCache.EXPECT().Get(clusterID, missingProject).Return(nil, apierrors.NewNotFound(schema.GroupResource{
		Group:    "management.cattle.io",
		Resource: "projects",
	}, missingProject)).AnyTimes()

	projectCache.EXPECT().Get(clusterID, badSpecProject).Return(&apisv3.Project{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: clusterID,
			Name:      projectID,
		},
		Spec: apisv3.ProjectSpec{
			ClusterName: missingCluster,
		},
	}, nil).AnyTimes()

	validator := projectroletemplatebinding.NewValidator(prtbResolver, crtbResolver, resolver, roleResolver, clusterCache, projectCache)
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
			name: "missing role template",
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
			name: "setting service account",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					basePRTB.ServiceAccount = "default"
					return basePRTB
				},
			},
			allowed: true,
		},
		{
			name: "setting a non project role template context",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.RoleTemplateName = "cluster-member"
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "neither user nor group nor service account subject is set",
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
			name: "both user and service account set",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = "newUser"
					basePRTB.ServiceAccount = "sa"
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "both group and service account set",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.UserName = ""
					basePRTB.GroupName = "newGroup"
					basePRTB.ServiceAccount = "sa"
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "bad role template name",
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
			wantErr: true,
		},
		{
			name: "locked role template",
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
		{
			name: "unset project name",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.ProjectName = ""
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "namespace and the project id part of the project name differ",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.ObjectMeta.Namespace = "default"
					basePRTB.ProjectName = fmt.Sprintf("%s:%s", clusterID, "p-cgtq4")
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "missing cluster name",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.ProjectName = fmt.Sprintf(":%s", projectID)
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "missing project name",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.ProjectName = fmt.Sprintf("%s:", clusterID)
					return basePRTB
				},
			},
			allowed: false,
		},

		{
			name: "missing cluster",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.ProjectName = fmt.Sprintf("%s:%s", missingCluster, projectID)
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "err when retrieving cluster",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.ProjectName = fmt.Sprintf("%s:%s", errCluster, projectID)
					return basePRTB
				},
			},
			allowed: false,
			wantErr: true,
		},
		{
			name: "nil return cluster",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.ProjectName = fmt.Sprintf("%s:%s", nilCluster, projectID)
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "missing project",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.Namespace = missingProject
					basePRTB.ProjectName = fmt.Sprintf("%s:%s", clusterID, missingProject)
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "err when retrieving project",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.Namespace = errProject
					basePRTB.ProjectName = fmt.Sprintf("%s:%s", clusterID, errProject)
					return basePRTB
				},
			},
			allowed: false,
			wantErr: true,
		},
		{
			name: "nil project",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.Namespace = nilProject
					basePRTB.ProjectName = fmt.Sprintf("%s:%s", clusterID, nilProject)
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "project spec cluster name does not match cluster",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.Namespace = badSpecProject
					basePRTB.ProjectName = fmt.Sprintf("%s:%s", clusterID, badSpecProject)
					return basePRTB
				},
			},
			allowed: false,
		},
		{
			name: "bad format projectName",
			args: args{
				username: adminUser,
				oldPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					return nil
				},
				newPRTB: func() *apisv3.ProjectRoleTemplateBinding {
					basePRTB := newBasePRTB()
					basePRTB.ProjectName = "default"
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
			req := createPRTBRequest(p.T(), test.args.oldPRTB(), test.args.newPRTB(), test.args.username)
			admitters := validator.Admitters()
			p.Len(admitters, 1)
			resp, err := admitters[0].Admit(req)
			if test.wantErr {
				p.Require().Error(err)
				p.Require().Nil(resp)
				return
			}
			p.Require().NoError(err, "Admit failed")
			if resp.Allowed != test.allowed {
				p.Failf("Response was incorrectly validated", "Wanted response.Allowed = %v got %v: result=%+v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

// createPRTBRequest will return a new webhookRequest with the using the given PRTBs
// if oldPRTB is nil then a request will be returned as a create operation.
// else the request will look like ana update operation.
func createPRTBRequest(t *testing.T, oldPRTB, newPRTB *apisv3.ProjectRoleTemplateBinding, username string) *admission.Request {
	t.Helper()
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "ProjectRoleTemplateBinding"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "projectroletemplatebindings"}
	req := &admission.Request{
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
		Context: context.Background(),
	}
	var err error
	req.Object.Raw, err = json.Marshal(newPRTB)
	assert.NoError(t, err, "Failed to marshal PRTB while creating request")
	if oldPRTB != nil {
		req.Operation = v1.Update
		req.OldObject.Raw, err = json.Marshal(oldPRTB)
		assert.NoError(t, err, "Failed to marshal PRTB while creating request")
	}

	return req
}

func newBasePRTB() *apisv3.ProjectRoleTemplateBinding {
	return &apisv3.ProjectRoleTemplateBinding{
		TypeMeta: metav1.TypeMeta{Kind: "ProjectRoleTemplateBinding", APIVersion: "management.cattle.io/v3"},
		ObjectMeta: metav1.ObjectMeta{
			Name:              "PRTB-new",
			GenerateName:      "PRTB-",
			Namespace:         projectID,
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
