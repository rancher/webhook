package globalrole_test

import (
	"testing"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/globalrole"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
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
			name: "escalation in global + cluster rules, and invalid RT, but only meta changed",
			args: args{
				newGR: func() *v3.GlobalRole {
					gr := newDefaultGR()
					gr.Labels = map[string]string{
						"new-label": "just-added",
					}
					gr.Rules = []v1.PolicyRule{ruleAdmin}
					return gr
				},
				oldGR: func() *v3.GlobalRole {
					gr := newDefaultGR()
					gr.Rules = []v1.PolicyRule{ruleAdmin}
					return gr
				},
			},
			allowed: true,
		},
		{
			name: "escalation in global + cluster rules, and invalid RT, but metadata and field changed",
			args: args{
				newGR: func() *v3.GlobalRole {
					gr := newDefaultGR()
					gr.Labels = map[string]string{
						"new-label": "just-added",
					}
					gr.Description = "new desc"
					gr.Rules = []v1.PolicyRule{ruleAdmin}
					return gr
				},
				oldGR: func() *v3.GlobalRole {
					gr := newDefaultGR()
					gr.Rules = []v1.PolicyRule{ruleAdmin}
					return gr
				},
			},
			allowed: false,
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
			},
			allowed: false,
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
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			state := newDefaultState(t)
			if test.args.stateSetup != nil {
				test.args.stateSetup(state)
			}
			grbResolver := state.createBaseGRBResolver()
			admitters := globalrole.NewValidator(state.resolver, grbResolver).Admitters()
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
	validator := globalrole.NewValidator(resolver, nil)
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
