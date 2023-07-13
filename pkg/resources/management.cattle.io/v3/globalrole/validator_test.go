package globalrole_test

import (
	"time"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/globalrole"
	v1 "k8s.io/api/admission/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const (
	adminUser = "admin-userid"
	testUser  = "test-userid"
	errorUser = "error-userid"
)

type TableTest struct {
	name    string
	args    args
	allowed bool
}

func (g *GlobalRoleSuite) Test_PrivilegeEscalation() {
	clusterRoles := []*rbacv1.ClusterRole{g.adminCR, g.readPodsCR}

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
			RoleRef: rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: g.readPodsCR.Name},
		},
	}
	resolver, _ := validation.NewTestRuleResolver(nil, nil, clusterRoles, clusterRoleBindings)
	validator := globalrole.NewValidator(resolver)
	admitters := validator.Admitters()
	g.Len(admitters, 1, "wanted only one admitter")
	admitter := admitters[0]

	tests := []TableTest{
		// base test, admin user correctly creates a global role
		{
			name: "base test valid privileges",
			args: args{
				username: adminUser,
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = g.adminCR.Rules
					return baseGR
				},
				oldGR: func() *apisv3.GlobalRole { return nil },
			},
			allowed: true,
		},

		// User attempts to create a globalrole with rules equal to one they hold.
		{
			name: "creating with equal privilege level",
			args: args{
				username: testUser,
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = g.readPodsCR.Rules
					return baseGR
				},
				oldGR: func() *apisv3.GlobalRole { return nil },
			},
			allowed: true,
		},

		// User attempts to create a globalrole with more rules than the ones they hold.
		{
			name: "creation with privilege escalation",
			args: args{
				username: testUser,
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = g.adminCR.Rules
					return baseGR
				},
				oldGR: func() *apisv3.GlobalRole { return nil },
			},
			allowed: false,
		},

		// User attempts to update a globalrole with more rules than the ones they hold.
		{
			name: "update with privilege escalation",
			args: args{
				username: testUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = g.readPodsCR.Rules
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = append(baseGR.Rules, g.ruleReadPods, g.ruleWriteNodes)
					return baseGR
				},
			},
			allowed: false,
		},
	}

	for i := range tests {
		test := tests[i]
		g.Run(test.name, func() {
			req := createGRRequest(g.T(), test.args.oldGR(), test.args.newGR(), test.args.username)
			resp, err := admitter.Admit(req)
			g.NoError(err, "Admit failed")
			g.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
		})
	}
}

func (g *GlobalRoleSuite) Test_UpdateValidation() {
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
	validator := globalrole.NewValidator(resolver)
	admitters := validator.Admitters()
	g.Len(admitters, 1, "wanted only one admitter")
	admitter := admitters[0]

	tests := []TableTest{
		{
			name: "base test valid GR annotation update",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = g.readPodsCR.Rules
					baseGR.Annotations = nil
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = g.readPodsCR.Rules
					baseGR.Annotations = map[string]string{"foo": "bar"}
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "update displayName",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = g.readPodsCR.Rules
					baseGR.DisplayName = "old display"
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = g.readPodsCR.Rules
					baseGR.DisplayName = "new display"
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "update displayName of builtin",
			args: args{
				username: testUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.DisplayName = "old display"
					baseGR.Builtin = true
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.DisplayName = "new display"
					baseGR.Builtin = true
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "update newUserDefault of builtin",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NewUserDefault = true
					baseGR.Builtin = true
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NewUserDefault = false
					baseGR.Builtin = true
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "update annotation of builtin",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = g.readPodsCR.Rules
					baseGR.Builtin = true
					baseGR.Annotations = nil
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = g.readPodsCR.Rules
					baseGR.Builtin = true
					baseGR.Annotations = map[string]string{"foo": "bar"}
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "update Builtin field",
			args: args{
				username: testUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Builtin = true
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Builtin = false
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "update empty rules",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []rbacv1.PolicyRule{g.ruleReadPods, g.ruleEmptyVerbs}
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []rbacv1.PolicyRule{g.ruleReadPods, g.ruleEmptyVerbs}
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "update empty rules being deleted",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []rbacv1.PolicyRule{g.ruleReadPods, g.ruleEmptyVerbs}
					return baseGR
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []rbacv1.PolicyRule{g.ruleReadPods, g.ruleEmptyVerbs}
					baseGR.DeletionTimestamp = &metav1.Time{Time: time.Now()}
					return baseGR
				},
			},
			allowed: true,
		},
	}

	for i := range tests {
		test := tests[i]
		g.Run(test.name, func() {
			req := createGRRequest(g.T(), test.args.oldGR(), test.args.newGR(), test.args.username)
			resp, err := admitter.Admit(req)
			g.NoError(err, "Admit failed")
			g.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
		})
	}
}

func (g *GlobalRoleSuite) Test_Create() {
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
	validator := globalrole.NewValidator(resolver)
	admitters := validator.Admitters()
	g.Len(admitters, 1, "wanted only one admitter")
	admitter := admitters[0]

	tests := []TableTest{
		{
			name: "base test valid GR",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					return nil
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []rbacv1.PolicyRule{g.ruleWriteNodes}
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "missing displayName",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					return nil
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.DisplayName = ""
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "missing rule verbs",
			args: args{
				username: adminUser,
				oldGR: func() *apisv3.GlobalRole {
					return nil
				},
				newGR: func() *apisv3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []rbacv1.PolicyRule{g.ruleReadPods, g.ruleEmptyVerbs}
					return baseGR
				},
			},
			allowed: false,
		},
	}

	for i := range tests {
		test := tests[i]
		g.Run(test.name, func() {
			// g.T().Parallel()
			req := createGRRequest(g.T(), test.args.oldGR(), test.args.newGR(), test.args.username)
			resp, err := admitter.Admit(req)
			g.NoError(err, "Admit failed")
			g.Equalf(test.allowed, resp.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, resp.Allowed, resp.Result)
		})
	}
}

func (g *GlobalRoleSuite) Test_ErrorHandling() {
	resolver, _ := validation.NewTestRuleResolver(nil, nil, nil, nil)
	validator := globalrole.NewValidator(resolver)
	admitters := validator.Admitters()
	g.Len(admitters, 1, "wanted only one admitter")
	admitter := admitters[0]
	req := createGRRequest(g.T(), newDefaultGR(), newDefaultGR(), testUser)
	req.Operation = v1.Connect
	_, err := admitter.Admit(req)
	g.Error(err, "Admit should fail on unknown handled operations")

	req = createGRRequest(g.T(), newDefaultGR(), newDefaultGR(), testUser)
	req.Object = runtime.RawExtension{}
	_, err = admitter.Admit(req)
	g.Error(err, "Admit should fail on bad request object")
}
