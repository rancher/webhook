package globalrolebinding_test

import (
	"time"

	"github.com/golang/mock/gomock"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/globalrolebinding"
	"github.com/rancher/wrangler/pkg/generic/fake"
	v1 "k8s.io/api/admission/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const (
	adminUser              = "admin-userid"
	testUser               = "test-userid"
	noPrivUser             = "no-priv-userid"
	newUser                = "newUser-userid"
	newGroupPrinc          = "local://group"
	testGroup              = "testGroup"
	notFoundGlobalRoleName = "not-found-globalRole"
)

func (g *GlobalRoleBindingSuite) Test_PrivilegeEscalation() {
	clusterRoles := []*rbacv1.ClusterRole{g.adminCR, g.manageNodeRole}

	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: g.adminCR.Name},
		},
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: testUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: g.manageNodeRole.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)

	ctrl := gomock.NewController(g.T())
	globalRoleCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.GlobalRole](ctrl)
	globalRoleCache.EXPECT().Get(g.adminGR.Name).Return(g.adminGR, nil).AnyTimes()
	globalRoleCache.EXPECT().Get(g.manageNodesGR.Name).Return(g.manageNodesGR, nil).AnyTimes()
	globalRoleCache.EXPECT().Get(notFoundGlobalRoleName).Return(nil, newNotFound(notFoundGlobalRoleName)).AnyTimes()
	globalRoleCache.EXPECT().Get("").Return(nil, newNotFound("")).AnyTimes()

	validator := globalrolebinding.NewValidator(globalRoleCache, resolver)
	admitters := validator.Admitters()
	g.Len(admitters, 1, "wanted only one admitter")
	admitter := admitters[0]

	tests := []tableTest{
		// base test, admin user correctly binding a different user to a globalRole {PASS}.
		{
			name: "base test valid privileges",
			args: args{
				username: adminUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = testUser
					baseGRB.GlobalRoleName = g.adminGR.Name
					return baseGRB
				},
				oldGRB: func() *apisv3.GlobalRoleBinding { return nil },
			},
			allowed: true,
		},

		// Test user escalates privileges to match their own {PASS}.
		{
			name: "binding to equal privilege level",
			args: args{
				username: testUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = noPrivUser
					baseGRB.GlobalRoleName = g.manageNodesGR.Name
					return baseGRB
				},
				oldGRB: func() *apisv3.GlobalRoleBinding { return nil },
			},
			allowed: true,
		},

		// Test user escalates privileges of another users that is greater then privileges held by the test user. {FAIL}.
		{
			name: "privilege escalation other user",
			args: args{
				username: testUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = noPrivUser
					baseGRB.GlobalRoleName = g.adminGR.Name
					return baseGRB
				},
				oldGRB: func() *apisv3.GlobalRoleBinding { return nil },
			},
			allowed: false,
		},

		// Users attempting to privilege escalate themselves  {FAIL}.
		{
			name: "privilege escalation self",
			args: args{
				username: testUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = testUser
					baseGRB.GlobalRoleName = g.adminGR.Name
					return baseGRB
				},
				oldGRB: func() *apisv3.GlobalRoleBinding { return nil },
			},
			allowed: false,
		},

		// Test that the privileges evaluated are those of the user in the request not the user being bound.  {FAIL}.
		{
			name: "correct user privileges are evaluated.",
			args: args{
				username: testUser,
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = adminUser
					baseGRB.GlobalRoleName = g.adminGR.Name
					return baseGRB
				},
				oldGRB: func() *apisv3.GlobalRoleBinding { return nil },
			},
			allowed: false,
		},

		// Test that if global role can not be found we reject the request.  {FAIL}.
		{
			name: "unknown globalRole",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					return baseGRB
				},
			},
			allowed: false,
		},

		// Test that if global role can not be found and we the operation is a delete operation we allow the request.  {PASS}.
		{
			name: "unknown globalRole being deleted",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
			},
			allowed: true,
		},
	}

	for i := range tests {
		test := tests[i]
		g.Run(test.name, func() {
			req := createGRBRequest(g.T(), test.args.oldGRB(), test.args.newGRB(), test.args.username)
			resp, err := admitter.Admit(req)
			g.NoError(err, "Admit failed")
			g.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
		})
	}
}

func (g *GlobalRoleBindingSuite) Test_UpdateValidation() {
	clusterRoles := []*rbacv1.ClusterRole{g.adminCR}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: g.adminCR.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)

	ctrl := gomock.NewController(g.T())
	globalRoleCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.GlobalRole](ctrl)
	globalRoleCache.EXPECT().Get(g.adminGR.Name).Return(g.adminGR, nil).AnyTimes()
	globalRoleCache.EXPECT().Get(notFoundGlobalRoleName).Return(nil, newNotFound(notFoundGlobalRoleName)).AnyTimes()

	validator := globalrolebinding.NewValidator(globalRoleCache, resolver)
	admitters := validator.Admitters()
	g.Len(admitters, 1, "wanted only one admitter")
	admitter := admitters[0]

	tests := []tableTest{
		{
			name: "base test valid GRB annotation update",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.Annotations = nil
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.Annotations = map[string]string{"foo": "bar"}
					return baseGRB
				},
			},
			allowed: true,
		},
		{
			name: "update GlobalRole",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = g.manageNodesGR.Name
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = g.adminGR.Name
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "unknown globalRole",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "unknown globalRole that is being deleted",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					baseGRB.DeletionTimestamp = &metav1.Time{Time: time.Now()}
					return baseGRB
				},
			},
			allowed: true,
		},
		{
			name: "update previously set user",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = adminUser
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = newUser
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "update previously unset user and set group ",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = ""
					baseGRB.GroupPrincipalName = testGroup
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = newUser
					baseGRB.GroupPrincipalName = testGroup
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "update previously set group principal",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = ""
					baseGRB.GroupPrincipalName = testGroup
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = ""
					baseGRB.GroupPrincipalName = newGroupPrinc
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "update previously unset group and set user ",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = adminUser
					baseGRB.GroupPrincipalName = ""
					return baseGRB
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = adminUser
					baseGRB.GroupPrincipalName = newGroupPrinc
					return baseGRB
				},
			},
			allowed: false,
		},
	}

	for i := range tests {
		test := tests[i]
		g.Run(test.name, func() {
			req := createGRBRequest(g.T(), test.args.oldGRB(), test.args.newGRB(), test.args.username)
			resp, err := admitter.Admit(req)
			g.NoError(err, "Admit failed")
			g.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
		})
	}
}

func (g *GlobalRoleBindingSuite) Test_Create() {
	clusterRoles := []*rbacv1.ClusterRole{g.adminCR}
	clusterRoleBindings := []*rbacv1.ClusterRoleBinding{
		{
			Subjects: []rbacv1.Subject{
				{Kind: rbacv1.UserKind, Name: adminUser},
			},
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: g.adminCR.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)

	ctrl := gomock.NewController(g.T())
	globalRoleCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.GlobalRole](ctrl)
	globalRoleCache.EXPECT().Get(g.adminGR.Name).Return(g.adminGR, nil).AnyTimes()
	globalRoleCache.EXPECT().Get(notFoundGlobalRoleName).Return(nil, newNotFound(notFoundGlobalRoleName)).AnyTimes()
	globalRoleCache.EXPECT().Get("").Return(nil, newNotFound(notFoundGlobalRoleName)).AnyTimes()

	validator := globalrolebinding.NewValidator(globalRoleCache, resolver)
	admitters := validator.Admitters()
	g.Len(admitters, 1, "wanted only one admitter")
	admitter := admitters[0]

	tests := []tableTest{
		{
			name: "base test valid GRB",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					return baseGRB
				},
			},
			allowed: true,
		},
		{
			name: "missing globalRole name",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = ""
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "missing user and group",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = ""
					baseGRB.GroupPrincipalName = ""
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "both user and group set",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = testUser
					baseGRB.GroupPrincipalName = testGroup
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "Group set but not user",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = ""
					baseGRB.GroupPrincipalName = testGroup
					return baseGRB
				},
			},
			allowed: true,
		},
		{
			name: "unknown globalRole",
			args: args{
				username: adminUser,
				oldGRB: func() *apisv3.GlobalRoleBinding {
					return nil
				},
				newGRB: func() *apisv3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundGlobalRoleName
					return baseGRB
				},
			},
			allowed: false,
		},
	}

	for i := range tests {
		test := tests[i]
		g.Run(test.name, func() {
			g.T().Parallel()
			req := createGRBRequest(g.T(), test.args.oldGRB(), test.args.newGRB(), test.args.username)
			resp, err := admitter.Admit(req)
			g.NoError(err, "Admit failed")
			g.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
		})
	}
}

func (g *GlobalRoleBindingSuite) Test_ErrorHandling() {
	const badGR = "badGR"

	resolver, _ := validation.NewTestRuleResolver(nil, nil, nil, nil)

	ctrl := gomock.NewController(g.T())
	globalRoleCache := fake.NewMockNonNamespacedCacheInterface[*apisv3.GlobalRole](ctrl)
	globalRoleCache.EXPECT().Get(badGR).Return(nil, errTest)

	validator := globalrolebinding.NewValidator(globalRoleCache, resolver)
	admitters := validator.Admitters()
	g.Len(admitters, 1, "wanted only one admitter")
	admitter := admitters[0]

	req := createGRBRequest(g.T(), newDefaultGRB(), newDefaultGRB(), testUser)
	req.Operation = v1.Connect
	_, err := admitter.Admit(req)
	g.Error(err, "Admit should fail on unknown handled operations")

	req = createGRBRequest(g.T(), newDefaultGRB(), newDefaultGRB(), testUser)
	req.Object = runtime.RawExtension{}
	_, err = admitter.Admit(req)
	g.Error(err, "Admit should fail on bad request object")

	newGRB := newDefaultGRB()
	newGRB.GlobalRoleName = badGR
	req = createGRBRequest(g.T(), nil, newGRB, testUser)
	_, err = admitter.Admit(req)
	g.Error(err, "Admit should fail on GlobalRole Get error")
}
