package globalrole_test

import (
	"fmt"
	"testing"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/globalrole"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	v1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	k8fake "k8s.io/client-go/kubernetes/typed/authorization/v1/fake"
	k8testing "k8s.io/client-go/testing"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

func TestAdmit(t *testing.T) {
	t.Parallel()
	lockedRoleTemplate := v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "locked",
		},
		Context: "cluster",
		Locked:  true,
		Rules: []v1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get"},
			},
		},
	}
	projectCtxRoleTemplate := v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "project-context",
		},
		Context: "project",
		Rules: []v1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get"},
			},
		},
	}
	noCtxRoleTemplate := v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "no-context",
		},
		Context: "",
		Rules: []v1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get"},
			},
		},
	}
	validRoleTemplate := v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "valid",
		},
		Context: "cluster",
		Rules: []v1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get"},
			},
		},
	}
	notFoundError := apierrors.NewNotFound(schema.GroupResource{Group: "management.cattle.io", Resource: "roletemplates"}, "not-found")
	tests := []testCase{
		{
			name: "new role not found roleTemplate",
			args: args{
				newGR: func() *v3.GlobalRole {
					gr := newDefaultGR()
					gr.InheritedClusterRoles = []string{"not-found"}
					return gr
				},
				stateSetup: func(ts testState) {
					ts.rtCacheMock.EXPECT().Get("not-found").Return(nil, notFoundError)
				},
			},
			allowed: false,
		},
		{
			name: "new role misc. error roleTemplate",
			args: args{
				newGR: func() *v3.GlobalRole {
					gr := newDefaultGR()
					gr.InheritedClusterRoles = []string{"error"}
					return gr
				},
				stateSetup: func(ts testState) {
					ts.rtCacheMock.EXPECT().Get("error").Return(nil, errServer)
				},
			},
			wantErr: true,
		},
		{
			name: "new role locked roleTemplate",
			args: args{
				newGR: func() *v3.GlobalRole {
					gr := newDefaultGR()
					gr.InheritedClusterRoles = []string{lockedRoleTemplate.Name}
					return gr
				},
				stateSetup: func(ts testState) {
					ts.rtCacheMock.EXPECT().Get(lockedRoleTemplate.Name).Return(&lockedRoleTemplate, nil)
				},
			},
			allowed: false,
		},
		{
			name: "new role project context roleTemplate",
			args: args{
				newGR: func() *v3.GlobalRole {
					gr := newDefaultGR()
					gr.InheritedClusterRoles = []string{projectCtxRoleTemplate.Name}
					return gr
				},
				stateSetup: func(ts testState) {
					ts.rtCacheMock.EXPECT().Get(projectCtxRoleTemplate.Name).Return(&projectCtxRoleTemplate, nil)
				},
			},
			allowed: false,
		},
		{
			name: "new role no context roleTemplate",
			args: args{
				newGR: func() *v3.GlobalRole {
					gr := newDefaultGR()
					gr.InheritedClusterRoles = []string{noCtxRoleTemplate.Name}
					return gr
				},
				stateSetup: func(ts testState) {
					ts.rtCacheMock.EXPECT().Get(noCtxRoleTemplate.Name).Return(&noCtxRoleTemplate, nil)
				},
			},
			allowed: false,
		},
		{
			name: "old role invalid roleTemplates, new role valid",
			args: args{
				oldGR: func() *v3.GlobalRole {
					gr := newDefaultGR()
					gr.InheritedClusterRoles = []string{noCtxRoleTemplate.Name, projectCtxRoleTemplate.Name, lockedRoleTemplate.Name}
					return gr
				},
				newGR: func() *v3.GlobalRole {
					gr := newDefaultGR()
					gr.InheritedClusterRoles = []string{validRoleTemplate.Name}
					return gr
				},
				stateSetup: func(ts testState) {
					ts.rtCacheMock.EXPECT().Get(validRoleTemplate.Name).Return(&validRoleTemplate, nil).AnyTimes()
				},
			},
			allowed: true,
		},
		{
			name: "creating with equal privilege level", // User attempts to create a globalrole with rules equal to one they hold.
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = readPodsCR.Rules
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "creation with privilege escalation", // User attempts to create a globalrole with more rules than the ones they hold.
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = adminCR.Rules
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: false,
		},
		{
			name: "creation with privilege escalation, escalate allowed",
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = adminCR.Rules
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(true, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: true,
		},
		{
			name: "creation with privilege escalation, escalate check failed",
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = adminCR.Rules
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(false, fmt.Errorf("server not available"), testUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: false,
		},
		{
			name: "update with privilege escalation", // User attempts to update a globalrole with more rules than the ones they hold.
			args: args{
				username: testUser,
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = readPodsCR.Rules
					return baseGR
				},
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = append(baseGR.Rules, ruleReadPods, ruleWriteNodes)
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: false,
		},
		{
			name: "update with privilege escalation, escalate allowed",
			args: args{
				username: testUser,
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = readPodsCR.Rules
					return baseGR
				},
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = append(baseGR.Rules, ruleReadPods, ruleWriteNodes)
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(true, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: true,
		},
		{
			name: "escalation in Cluster Rules", // User attempts to create a global with a cluster rules it does not currently have
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					gr := newDefaultGR()
					gr.InheritedClusterRoles = []string{roleTemplate.Name}
					return gr
				},
				stateSetup: func(state testState) {
					state.rtCacheMock.EXPECT().Get(roleTemplate.Name).Return(&roleTemplate, nil).AnyTimes()
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: false,
		},
		{
			name: "escalation in Cluster Rules, escalate allowed",
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					gr := newDefaultGR()
					gr.InheritedClusterRoles = []string{roleTemplate.Name}
					return gr
				},
				stateSetup: func(state testState) {
					state.rtCacheMock.EXPECT().Get(roleTemplate.Name).Return(&roleTemplate, nil).AnyTimes()
					setSarResponse(true, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: true,
		},
		{
			name: "escalation in Cluster Rules, escalate check failed",
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					gr := newDefaultGR()
					gr.InheritedClusterRoles = []string{roleTemplate.Name}
					return gr
				},
				stateSetup: func(state testState) {
					state.rtCacheMock.EXPECT().Get(roleTemplate.Name).Return(&roleTemplate, nil).AnyTimes()
					setSarResponse(false, fmt.Errorf("server not available"), testUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: false,
		},
		{
			name: "error in GR cluster rules resolver", // User attempts to create a globalRole but there are errors in the rule resolver.
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					gr := newDefaultGR()
					gr.InheritedClusterRoles = []string{"error"}
					return gr
				},
				stateSetup: func(state testState) {
					state.rtCacheMock.EXPECT().Get("error").Return(&v3.RoleTemplate{
						ObjectMeta: metav1.ObjectMeta{
							Name: "error",
						},
						Rules: []v1.PolicyRule{
							{
								APIGroups: []string{""},
								Resources: []string{"pods"},
								Verbs:     []string{"get"},
							},
						},
						Context: "cluster",
					}, nil)
					state.rtCacheMock.EXPECT().Get("error").Return(nil, errServer)
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},
			wantErr: true,
		},
		{
			name: "base test valid GR update",
			args: args{
				oldGR: newDefaultGR,
				newGR: newDefaultGR,
			},
			allowed: true,
		},
		{
			name: "update displayName",
			args: args{
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.DisplayName = "old display"
					return baseGR
				},
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.DisplayName = "new display"
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "update displayName of builtin",
			args: args{
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.DisplayName = "old display"
					baseGR.Builtin = true
					return baseGR
				},
				newGR: func() *v3.GlobalRole {
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
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NewUserDefault = true
					baseGR.Builtin = true
					return baseGR
				},
				newGR: func() *v3.GlobalRole {
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
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Builtin = true
					baseGR.Annotations = nil
					return baseGR
				},
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Builtin = true
					baseGR.Annotations = map[string]string{"foo": "bar"}
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "update Builtin field to false",
			args: args{
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Builtin = true
					return baseGR
				},
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Builtin = false
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "update Builtin field to true",
			args: args{
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Builtin = false
					return baseGR
				},
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Builtin = true
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "update empty rules",
			args: args{
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []v1.PolicyRule{ruleReadPods, ruleEmptyVerbs}
					return baseGR
				},
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []v1.PolicyRule{ruleReadPods, ruleEmptyVerbs}
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "update empty rules being deleted",
			args: args{
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []v1.PolicyRule{ruleReadPods, ruleEmptyVerbs}
					return baseGR
				},
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []v1.PolicyRule{ruleReadPods, ruleEmptyVerbs}
					baseGR.DeletionTimestamp = &metav1.Time{Time: time.Now()}
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "base test valid GR create",
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []v1.PolicyRule{ruleReadPods}
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "create missing rule verbs",
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []v1.PolicyRule{ruleReadPods, ruleEmptyVerbs}
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "can delete non builtin",
			args: args{
				username: testUser,
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []v1.PolicyRule{ruleAdmin}
					return baseGR
				},
			},
			allowed: true,
		},
		{
			name: "can not delete builtin",
			args: args{
				username: testUser,
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []v1.PolicyRule{ruleAdmin}
					baseGR.Builtin = true
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "can not create builtin roles",
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Builtin = true
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "creating with escalation in NamespacedRules",
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NamespacedRules = map[string][]v1.PolicyRule{
						"ns1": {ruleAdmin},
						"ns2": {ruleReadPods},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(false, nil, adminUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: false,
		},
		{
			name: "creating with escalation in NamespacedRules, escalate allowed",
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NamespacedRules = map[string][]v1.PolicyRule{
						"ns1": {ruleAdmin},
						"ns2": {ruleReadPods},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(true, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: true,
		},
		{
			name: "creating with allowed NamespacedRules",
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NamespacedRules = map[string][]v1.PolicyRule{
						"ns1": {ruleReadPods},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},

			allowed: true,
		},
		{
			name: "creating with multiple allowed NamespacedRules, multiple namespaces",
			args: args{
				username: adminUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NamespacedRules = map[string][]v1.PolicyRule{
						"ns1": {ruleReadPods},
						"ns2": {ruleWriteNodes, ruleReadPods},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(false, nil, adminUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: true,
		},
		{
			name: "creating with NamespacedRules that has no rule",
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NamespacedRules = map[string][]v1.PolicyRule{
						"ns1": {},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: true,
		},
		{
			name: "update in NamespacedRules with privilege escalation",
			args: args{
				username: testUser,
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NamespacedRules = map[string][]v1.PolicyRule{
						"ns1": {ruleReadPods},
					}
					return baseGR
				},
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NamespacedRules = map[string][]v1.PolicyRule{
						"ns1": {ruleAdmin},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: false,
		},
		{
			name: "update in NamespacedRules with privilege escalation, escalate allowed",
			args: args{
				username: testUser,
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NamespacedRules = map[string][]v1.PolicyRule{
						"ns1": {ruleReadPods},
					}
					return baseGR
				},
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NamespacedRules = map[string][]v1.PolicyRule{
						"ns1": {ruleAdmin},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(true, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: true,
		},
		{
			name: "rules contains PolicyRule that is invalid",
			args: args{
				username: adminUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.Rules = []v1.PolicyRule{
						{
							APIGroups: []string{""},
							Resources: []string{"pods"},
							Verbs:     []string{},
						}}
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "namespacedrules contains PolicyRule that is invalid",
			args: args{
				username: adminUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.NamespacedRules = map[string][]v1.PolicyRule{
						"ns1": {{
							APIGroups: []string{""},
							Resources: []string{"pods"},
							Verbs:     []string{},
						}},
					}
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "allowed InheritedFleetWorkspacePermissions",
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.InheritedFleetWorkspacePermissions = &v3.FleetWorkspacePermission{
						ResourceRules: []v1.PolicyRule{
							ruleReadPods,
						},
						WorkspaceVerbs: []string{
							"GET",
						},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},

			allowed: true,
		},
		{
			name: "not allowed InheritedFleetWorkspacePermissions.ResourceRules",
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.InheritedFleetWorkspacePermissions = &v3.FleetWorkspacePermission{
						ResourceRules: []v1.PolicyRule{
							ruleAdmin,
						},
						WorkspaceVerbs: []string{
							"GET",
						},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},

			allowed: false,
		},
		{
			name: "not allowed InheritedFleetWorkspacePermissions.WorkspaceVerbs",
			args: args{
				username: testUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.InheritedFleetWorkspacePermissions = &v3.FleetWorkspacePermission{
						ResourceRules: []v1.PolicyRule{
							ruleReadPods,
						},
						WorkspaceVerbs: []string{
							"*",
						},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},

			allowed: false,
		},
		{
			name: "InheritedFleetWorkspacePermissions rules contains PolicyRule that is invalid",
			args: args{
				username: adminUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.InheritedFleetWorkspacePermissions = &v3.FleetWorkspacePermission{
						ResourceRules: []v1.PolicyRule{
							{
								APIGroups: []string{""},
								Resources: []string{"pods"},
								Verbs:     []string{},
							},
						},
					}
					return baseGR
				},
			},
			allowed: false,
		},
		{
			name: "InheritedFleetWorkspacePermissions rules contains empty WorkspaceVerbs",
			args: args{
				username: adminUser,
				rawNewGR: []byte(`{"kind":"GlobalRole","apiVersion":"management.cattle.io/v3","metadata":{"name":"gr-new","generateName":"gr-","namespace":"c-namespace","uid":"6534e4ef-f07b-4c61-b88d-95a92cce4852","resourceVersion":"1","generation":1,"creationTimestamp":null},"displayName":"Test Global Role","description":"This is a role created for testing.","inheritedFleetWorkspacePermissions":{"resourceRules":[{"verbs":["GET","WATCH"],"apiGroups":["v1"],"resources":["pods"]}], "workspaceVerbs":[]},"status":{}}`),
			},
			allowed: false,
		},
		{
			name: "update in InheritedFleetWorkspacePermissions with privilege escalation",
			args: args{
				username: testUser,
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.InheritedFleetWorkspacePermissions = &v3.FleetWorkspacePermission{
						ResourceRules: []v1.PolicyRule{
							ruleReadPods,
						},
					}
					return baseGR
				},
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.InheritedFleetWorkspacePermissions = &v3.FleetWorkspacePermission{
						ResourceRules: []v1.PolicyRule{
							ruleAdmin,
						},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: false,
		},
		{
			name: "update in InheritedFleetWorkspacePermissions with privilege escalation, escalate allowed",
			args: args{
				username: testUser,
				oldGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.InheritedFleetWorkspacePermissions = &v3.FleetWorkspacePermission{
						ResourceRules: []v1.PolicyRule{
							ruleReadPods,
						},
					}
					return baseGR
				},
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.InheritedFleetWorkspacePermissions = &v3.FleetWorkspacePermission{
						ResourceRules: []v1.PolicyRule{
							ruleAdmin,
						},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					setSarResponse(true, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},
			allowed: true,
		},
		{
			name: "restricted admin can create GR with InheritedFleetWorkspacePermissions and fleet rules",
			args: args{
				username: restrictedAdminUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.InheritedFleetWorkspacePermissions = &v3.FleetWorkspacePermission{
						ResourceRules: []v1.PolicyRule{
							{
								Verbs:     []string{"get", "list", "create", "delete"},
								APIGroups: []string{"fleet.cattle.io"},
								Resources: []string{"bundles", "gitrepos"},
							},
						},
						WorkspaceVerbs: []string{
							"get",
							"create",
						},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					state.grCacheMock.EXPECT().Get(restrictedAdminGR.Name).Return(&restrictedAdminGR, nil).AnyTimes()
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},

			allowed: true,
		},
		{
			name: "restricted admin can create GR with InheritedFleetWorkspacePermissions and fleet rules and *",
			args: args{
				username: restrictedAdminUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.InheritedFleetWorkspacePermissions = &v3.FleetWorkspacePermission{
						ResourceRules: []v1.PolicyRule{
							{
								Verbs:     []string{"*"},
								APIGroups: []string{"fleet.cattle.io"},
								Resources: []string{"bundles", "gitrepos"},
							},
						},
						WorkspaceVerbs: []string{
							"*",
						},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					state.grCacheMock.EXPECT().Get(restrictedAdminGR.Name).Return(&restrictedAdminGR, nil).AnyTimes()
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},

			allowed: true,
		},
		{
			name: "restricted admin can't create GR with InheritedFleetWorkspacePermissions and pod rules",
			args: args{
				username: restrictedAdminUser,
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.InheritedFleetWorkspacePermissions = &v3.FleetWorkspacePermission{
						ResourceRules: []v1.PolicyRule{
							{
								Verbs:     []string{"get", ""},
								APIGroups: []string{""},
								Resources: []string{"pods"},
							},
						},
						WorkspaceVerbs: []string{
							"get",
							"create",
						},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					state.grCacheMock.EXPECT().Get(restrictedAdminGR.Name).Return(&restrictedAdminGR, nil).AnyTimes()
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},

			allowed: false,
		},
		{
			name: "restricted admin can update GR with InheritedFleetWorkspacePermissions and fleet rules",
			args: args{
				username: restrictedAdminUser,
				oldGR: func() *v3.GlobalRole {
					return newDefaultGR()
				},
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.InheritedFleetWorkspacePermissions = &v3.FleetWorkspacePermission{
						ResourceRules: []v1.PolicyRule{
							{
								Verbs:     []string{"get", "list", "create", "delete"},
								APIGroups: []string{"fleet.cattle.io"},
								Resources: []string{"bundles", "gitrepos"},
							},
						},
						WorkspaceVerbs: []string{
							"get",
							"create",
						},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					state.grCacheMock.EXPECT().Get(restrictedAdminGR.Name).Return(&restrictedAdminGR, nil).AnyTimes()
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},

			allowed: true,
		},
		{
			name: "restricted admin can update GR with InheritedFleetWorkspacePermissions and fleet rules and *",
			args: args{
				username: restrictedAdminUser,
				oldGR: func() *v3.GlobalRole {
					return newDefaultGR()
				},
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.InheritedFleetWorkspacePermissions = &v3.FleetWorkspacePermission{
						ResourceRules: []v1.PolicyRule{
							{
								Verbs:     []string{"*"},
								APIGroups: []string{"fleet.cattle.io"},
								Resources: []string{"bundles", "gitrepos"},
							},
						},
						WorkspaceVerbs: []string{
							"*",
						},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					state.grCacheMock.EXPECT().Get(restrictedAdminGR.Name).Return(&restrictedAdminGR, nil).AnyTimes()
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},

			allowed: true,
		},
		{
			name: "restricted admin can't update GR with InheritedFleetWorkspacePermissions and pod rules",
			args: args{
				username: restrictedAdminUser,
				oldGR: func() *v3.GlobalRole {
					return newDefaultGR()
				},
				newGR: func() *v3.GlobalRole {
					baseGR := newDefaultGR()
					baseGR.InheritedFleetWorkspacePermissions = &v3.FleetWorkspacePermission{
						ResourceRules: []v1.PolicyRule{
							{
								Verbs:     []string{"get", ""},
								APIGroups: []string{""},
								Resources: []string{"pods"},
							},
						},
						WorkspaceVerbs: []string{
							"get",
							"create",
						},
					}
					return baseGR
				},
				stateSetup: func(state testState) {
					state.grCacheMock.EXPECT().Get(restrictedAdminGR.Name).Return(&restrictedAdminGR, nil).AnyTimes()
					setSarResponse(false, nil, testUser, newDefaultGR().Name, state.sarMock)
				},
			},

			allowed: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			state := newDefaultState(t)
			if test.args.stateSetup != nil {
				test.args.stateSetup(state)
			}
			grResolver := state.createBaseGRResolver()
			grbResolvers := state.createBaseGRBResolvers(grResolver)
			admitters := globalrole.NewValidator(state.resolver, grbResolvers, state.sarMock, grResolver).Admitters()
			assert.Len(t, admitters, 1)

			req := createGRRequest(t, test)
			response, err := admitters[0].Admit(req)
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equalf(t, test.allowed, response.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, response.Allowed, response.Result)
		})
	}
}

func Test_UnexpectedErrors(t *testing.T) {
	t.Parallel()
	resolver, _ := validation.NewTestRuleResolver(nil, nil, nil, nil)
	validator := globalrole.NewValidator(resolver, nil, nil, nil)
	admitters := validator.Admitters()
	require.Len(t, admitters, 1, "wanted only one admitter")
	test := testCase{
		args: args{
			oldGR:    newDefaultGR,
			newGR:    newDefaultGR,
			username: testUser,
		},
	}
	req := createGRRequest(t, test)
	req.Object = runtime.RawExtension{}
	_, err := admitters[0].Admit(req)
	require.Error(t, err, "Admit should fail on bad request object")
	req = createGRRequest(t, test)
	req.Operation = admissionv1.Connect
	_, err = admitters[0].Admit(req)
	require.Error(t, err, "Admit should fail on unhandled operations")
}

func setSarResponse(allowed bool, testErr error, targetUser string, targetGrName string, sarMock *k8fake.FakeSubjectAccessReviews) {
	sarMock.Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
		createAction := action.(k8testing.CreateActionImpl)
		review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
		spec := review.Spec

		isForGRGVR := spec.ResourceAttributes.Group == "management.cattle.io" && spec.ResourceAttributes.Version == "v3" &&
			spec.ResourceAttributes.Resource == "globalroles"
		if spec.User == targetUser && spec.ResourceAttributes.Verb == "escalate" &&
			spec.ResourceAttributes.Namespace == "" && spec.ResourceAttributes.Name == targetGrName && isForGRGVR {
			review.Status.Allowed = allowed
			return true, review, testErr
		}
		return false, nil, nil
	})
}
