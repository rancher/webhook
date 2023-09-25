package globalrolebinding_test

import (
	"testing"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/resolvers"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/globalrolebinding"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestAdmit(t *testing.T) {
	t.Parallel()
	tests := []testCase{
		{
			name: "create global role not found",
			args: args{
				newGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.GlobalRoleName = notFoundName
					return gr
				},
			},
			allowed: false,
		},
		{
			name: "update gr not found, grb not deleting",
			args: args{
				newGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.GlobalRoleName = notFoundName
					return gr
				},
				oldGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.GlobalRoleName = notFoundName
					return gr
				},
			},
			allowed: false,
		},
		{
			name: "update gr not found, grb deleting",
			args: args{
				newGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.GlobalRoleName = notFoundName
					gr.DeletionTimestamp = &metav1.Time{Time: time.Now()}
					return gr
				},
				oldGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.GlobalRoleName = notFoundName
					gr.UserName = notFoundName
					return gr
				},
			},
			allowed: true,
		},
		{
			name: "update gr refers to not found RT",
			args: args{
				newGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.GlobalRoleName = notFoundRoleGR.Name
					return gr
				},
				oldGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.GlobalRoleName = notFoundRoleGR.Name
					return gr
				},
				stateSetup: func(ts testState) {
					ts.grCacheMock.EXPECT().Get(notFoundRoleGR.Name).Return(&notFoundRoleGR, nil)
					ts.rtCacheMock.EXPECT().Get(notFoundName).Return(nil, newNotFound(notFoundName))
				},
			},
			allowed: false,
		},
		{
			name: "create gr refers to locked RT",
			args: args{
				newGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.GlobalRoleName = lockedRoleGR.Name
					return gr
				},
				stateSetup: func(ts testState) {
					ts.grCacheMock.EXPECT().Get(lockedRoleGR.Name).Return(&lockedRoleGR, nil)
					ts.rtCacheMock.EXPECT().Get(lockedRT.Name).Return(&lockedRT, nil)
				},
			},
			allowed: false,
		},
		{
			name: "create gr refers to not found RT",
			args: args{
				newGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.GlobalRoleName = notFoundRoleGR.Name
					return gr
				},
				stateSetup: func(ts testState) {
					ts.grCacheMock.EXPECT().Get(notFoundRoleGR.Name).Return(&notFoundRoleGR, nil)
					ts.rtCacheMock.EXPECT().Get(notFoundName).Return(nil, newNotFound(notFoundName))
				},
			},
			allowed: false,
		},
		{
			name: "create gr refers to RT misc error",
			args: args{
				newGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.GlobalRoleName = errorRoleGR.Name
					return gr
				},
				stateSetup: func(ts testState) {
					ts.grCacheMock.EXPECT().Get(errorRoleGR.Name).Return(&errorRoleGR, nil)
					ts.rtCacheMock.EXPECT().Get(errName).Return(nil, errServer)
				},
			},
			wantError: true,
		},
		{
			name: "update gr refers to RT misc error",
			args: args{
				newGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.GlobalRoleName = errorRoleGR.Name
					return gr
				},
				oldGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.GlobalRoleName = errorRoleGR.Name
					return gr
				},
				stateSetup: func(ts testState) {
					ts.grCacheMock.EXPECT().Get(errorRoleGR.Name).Return(&errorRoleGR, nil)
					ts.rtCacheMock.EXPECT().Get(errName).Return(nil, errServer)
				},
			},
			wantError: true,
		},
		{
			name: "update gr refers to locked RT",
			args: args{
				newGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.GlobalRoleName = lockedRoleGR.Name
					return gr
				},
				oldGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.GlobalRoleName = lockedRoleGR.Name
					return gr
				},
				stateSetup: func(ts testState) {
					ts.grCacheMock.EXPECT().Get(lockedRoleGR.Name).Return(&lockedRoleGR, nil)
					ts.rtCacheMock.EXPECT().Get(lockedRT.Name).Return(&lockedRT, nil)
				},
			},
			allowed: true,
		},
		{
			name: "update meta-only changed",
			args: args{
				newGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.Labels = map[string]string{"updated": "yes"}
					gr.GlobalRoleName = errName
					return gr
				},
				oldGRB: func() *v3.GlobalRoleBinding {
					gr := newDefaultGRB()
					gr.GlobalRoleName = errName
					return gr
				},
			},
			allowed: true,
		},
		// Start privilege test
		{
			name: "base test valid privileges",
			args: args{
				username: adminUser,
				newGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = testUser
					baseGRB.GlobalRoleName = adminGR.Name
					return baseGRB
				},
				oldGRB: func() *v3.GlobalRoleBinding { return nil },
			},
			allowed: true,
		},
		{
			name: "binding to equal privilege level",
			args: args{
				username: testUser,
				newGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = noPrivUser
					baseGRB.GlobalRoleName = baseGR.Name
					return baseGRB
				},
				oldGRB: func() *v3.GlobalRoleBinding { return nil },
			},
			allowed: true,
		},
		{
			name: "privilege escalation other user",
			args: args{
				username: testUser,
				newGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = noPrivUser
					baseGRB.GlobalRoleName = adminGR.Name
					return baseGRB
				},
				oldGRB: func() *v3.GlobalRoleBinding { return nil },
			},
			allowed: false,
		},
		{
			name: "privilege escalation self",
			args: args{
				username: testUser,
				newGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = testUser
					baseGRB.GlobalRoleName = adminGR.Name
					return baseGRB
				},
				oldGRB: func() *v3.GlobalRoleBinding { return nil },
			},
			allowed: false,
		},
		{
			name: "correct user privileges are evaluated.", // test that the privileges evaluated are those of the user in the request not the user being bound.
			args: args{
				username: testUser,
				newGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = adminUser
					baseGRB.GlobalRoleName = adminGR.Name
					return baseGRB
				},
				oldGRB: func() *v3.GlobalRoleBinding { return nil },
			},
			allowed: false,
		},
		{
			name: "escalation in GR Cluster Roles",
			args: args{
				newGRB: func() *v3.GlobalRoleBinding {
					return &v3.GlobalRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name: "test-grb",
						},
						UserName:       testUser,
						GlobalRoleName: adminClusterGR.Name,
					}
				},
				stateSetup: func(ts testState) {
					ts.grCacheMock.EXPECT().Get(adminClusterGR.Name).Return(&adminClusterGR, nil)
					ts.rtCacheMock.EXPECT().Get(adminRT.Name).Return(&adminRT, nil).AnyTimes()
				},
			},
			allowed: false,
		},
		{
			name: "not found error resolving rules",
			args: args{
				newGRB: func() *v3.GlobalRoleBinding {
					return &v3.GlobalRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name: "test-grb",
						},
						UserName:       testUser,
						GlobalRoleName: notFoundRoleGR.Name,
					}
				},
				stateSetup: func(ts testState) {
					notFoundError := apierrors.NewNotFound(schema.GroupResource{
						Group:    "management.cattle.io",
						Resource: "roletemplates",
					}, notFoundName)
					ts.grCacheMock.EXPECT().Get(notFoundRoleGR.Name).Return(&notFoundRoleGR, nil)
					ts.rtCacheMock.EXPECT().Get(notFoundName).Return(nil, notFoundError)
				},
			},
			allowed: false,
		},
		{
			name: "error getting global role",
			args: args{
				newGRB: func() *v3.GlobalRoleBinding {
					return &v3.GlobalRoleBinding{
						ObjectMeta: metav1.ObjectMeta{
							Name: "test-grb",
						},
						UserName:       testUser,
						GlobalRoleName: errName,
					}
				},
				stateSetup: func(ts testState) {
					ts.grCacheMock.EXPECT().Get(errName).Return(nil, errServer)
				},
			},
			wantError: true,
		},
		{
			name: "base test valid GRB annotation update",
			args: args{
				username: adminUser,
				oldGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.Annotations = nil
					return baseGRB
				},
				newGRB: func() *v3.GlobalRoleBinding {
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
				oldGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = baseGR.Name
					return baseGRB
				},
				newGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = adminGR.Name
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "unknown globalRole",
			args: args{
				username: adminUser,
				oldGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundName
					return baseGRB
				},
				newGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundName
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "unknown globalRole that is being deleted",
			args: args{
				username: adminUser,
				oldGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundName
					return baseGRB
				},
				newGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundName
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
				oldGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = adminUser
					return baseGRB
				},
				newGRB: func() *v3.GlobalRoleBinding {
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
				oldGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = ""
					baseGRB.GroupPrincipalName = testGroup
					return baseGRB
				},
				newGRB: func() *v3.GlobalRoleBinding {
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
				oldGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = ""
					baseGRB.GroupPrincipalName = testGroup
					return baseGRB
				},
				newGRB: func() *v3.GlobalRoleBinding {
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
				oldGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = adminUser
					baseGRB.GroupPrincipalName = ""
					return baseGRB
				},
				newGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.UserName = adminUser
					baseGRB.GroupPrincipalName = newGroupPrinc
					return baseGRB
				},
			},
			allowed: false,
		},
		{
			name: "base test valid GRB",
			args: args{
				username: adminUser,
				newGRB: func() *v3.GlobalRoleBinding {
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
				newGRB: func() *v3.GlobalRoleBinding {
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
				newGRB: func() *v3.GlobalRoleBinding {
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
				newGRB: func() *v3.GlobalRoleBinding {
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
				newGRB: func() *v3.GlobalRoleBinding {
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
				newGRB: func() *v3.GlobalRoleBinding {
					baseGRB := newDefaultGRB()
					baseGRB.GlobalRoleName = notFoundName
					return baseGRB
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
			grResolver := auth.NewGlobalRoleResolver(auth.NewRoleTemplateResolver(state.rtCacheMock, nil), state.grCacheMock)
			grbResolver := resolvers.NewGRBClusterRuleResolver(state.grbCacheMock, grResolver, nil)
			admitters := globalrolebinding.NewValidator(state.resolver, grbResolver).Admitters()
			require.Len(t, admitters, 1)

			req := createGRBRequest(t, test)

			response, err := admitters[0].Admit(req)
			if test.wantError {
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
	state := newDefaultState(t)
	grResolver := auth.NewGlobalRoleResolver(auth.NewRoleTemplateResolver(state.rtCacheMock, nil), state.grCacheMock)
	grbResolver := resolvers.NewGRBClusterRuleResolver(state.grbCacheMock, grResolver, nil)
	validator := globalrolebinding.NewValidator(state.resolver, grbResolver)
	admitters := validator.Admitters()
	require.Len(t, admitters, 1, "wanted only one admitter")
	admitter := admitters[0]
	test := testCase{
		args: args{
			newGRB: newDefaultGRB,
			oldGRB: newDefaultGRB,
		},
	}

	req := createGRBRequest(t, test)
	req.Operation = v1.Connect
	_, err := admitter.Admit(req)
	require.Error(t, err, "Admit should fail on unknown handled operations")

	req = createGRBRequest(t, test)
	req.Object = runtime.RawExtension{}
	_, err = admitter.Admit(req)
	require.Error(t, err, "Admit should fail on bad request object")
}
