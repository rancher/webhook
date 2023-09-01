package globalrole

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/resolvers"
	"github.com/rancher/wrangler/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authenicationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

var (
	globalRoleGVR = metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "globalRoles"}
	globalRoleGVK = metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "GlobalRole"}
	clusterRole   = v1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cr",
		},
		Rules: []v1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "configmaps"},
				Verbs:     []string{"get"},
			},
		},
	}
	clusterRoleBinding = v1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-crb",
		},
		RoleRef: v1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterRole.Name,
		},
		Subjects: []v1.Subject{
			{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "User",
				Name:     "test-user",
			},
		},
	}
	baseRT = v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "base-rt",
		},
		Rules: []v1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "configmaps"},
				Verbs:     []string{"get"},
			},
		},
	}
	baseGR = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "base-gr",
		},
		Rules: []v1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "configmaps"},
				Verbs:     []string{"get"},
			},
		},
		InheritedClusterRoles: []string{baseRT.Name},
	}
	baseGRB = v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "base-grb",
		},
		GlobalRoleName: baseGR.Name,
		UserName:       "test-user",
	}
)

func TestAdmitInvalidOrDeletedGlobalRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		globalRole v3.GlobalRole
		wantError  bool
		wantAdmit  bool
	}{
		{
			name: "global role in the process of being deleted is admitted",
			globalRole: v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					DeletionTimestamp: admission.Ptr(metav1.NewTime(time.Now())),
				},
			},
			wantAdmit: true,
		},
		{
			name: "a policy rule lacks a verb",
			globalRole: v3.GlobalRole{
				Rules: []v1.PolicyRule{
					{
						Verbs: []string{"list"},
					},
					{
						Verbs: nil,
					},
				},
			},
			wantAdmit: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			// The resolver should not run in these tests. Making it not nil to get test errors instead of panics.
			resolver, _ := validation.NewTestRuleResolver(nil, nil, nil, nil)

			ctrl := gomock.NewController(t)
			rtCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
			grbResolver := createBaseGRBResolver(ctrl, rtCache)
			admitters := NewValidator(resolver, grbResolver).Admitters()
			assert.Len(t, admitters, 1)

			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation:       admissionv1.Create,
					UID:             "2",
					Kind:            globalRoleGVK,
					Resource:        globalRoleGVR,
					RequestKind:     &globalRoleGVK,
					RequestResource: &globalRoleGVR,
					Name:            "my-global-role",
					UserInfo:        authenicationv1.UserInfo{Username: "test-user", UID: ""},
					Object:          runtime.RawExtension{},
					OldObject:       runtime.RawExtension{},
				},
			}
			var err error
			req.Object.Raw, err = json.Marshal(test.globalRole)
			require.NoError(t, err, "Failed to marshal new GlobalRole while creating request")

			response, err := admitters[0].Admit(&req)
			if test.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.wantAdmit, response.Allowed)
			}
		})
	}
}

func TestRejectsBadRequest(t *testing.T) {
	t.Parallel()
	// The resolver should not run in these tests. Making it not nil to get test errors instead of panics.
	resolver, _ := validation.NewTestRuleResolver(nil, nil, nil, nil)
	admitters := NewValidator(resolver, nil).Admitters()
	assert.Len(t, admitters, 1)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation:       admissionv1.Create,
			UID:             "2",
			Kind:            globalRoleGVK,
			Resource:        globalRoleGVR,
			RequestKind:     &globalRoleGVK,
			RequestResource: &globalRoleGVR,
			Name:            "my-global-role",
			UserInfo:        authenicationv1.UserInfo{Username: "test-user", UID: ""},
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
	}

	_, err := admitters[0].Admit(&req)
	require.Error(t, err)
}

func TestAdmitValidGlobalRole(t *testing.T) {
	t.Parallel()
	// The resolver should not run in these tests. Making it not nil to get test errors instead of panics.
	resolver, _ := validation.NewTestRuleResolver(nil, nil, nil, nil)
	ctrl := gomock.NewController(t)
	rtCache := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
	grbResolver := createBaseGRBResolver(ctrl, rtCache)

	admitters := NewValidator(resolver, grbResolver).Admitters()
	assert.Len(t, admitters, 1)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			UserInfo:  authenicationv1.UserInfo{Username: "test-user", UID: ""},
		},
	}
	var err error
	req.Object.Raw, err = json.Marshal(v3.GlobalRole{})
	require.NoError(t, err, "Failed to marshal new GlobalRole while creating request")

	response, err := admitters[0].Admit(&req)
	require.NoError(t, err)
	assert.True(t, response.Allowed)
}

func TestRejectsEscalation(t *testing.T) {
	t.Parallel()
	type testState struct {
		rtCacheMock *fake.MockNonNamespacedCacheInterface[*v3.RoleTemplate]
	}

	roleTemplate := v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-rt",
		},
		Context: "cluster",
		Rules: []v1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"*"},
			},
		},
	}
	tests := []struct {
		name       string
		globalRole v3.GlobalRole
		stateSetup func(testState)
		wantError  bool
		wantAdmit  bool
	}{
		{
			name: "escalation in Global Rules",
			globalRole: v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				Rules: []v1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"*"},
					},
				},
			},
			wantAdmit: false,
		},
		{
			name: "escalation in Cluster Rules",
			globalRole: v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				Rules: []v1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
				InheritedClusterRoles: []string{roleTemplate.Name},
			},
			stateSetup: func(state testState) {
				state.rtCacheMock.EXPECT().Get(roleTemplate.Name).Return(&roleTemplate, nil).AnyTimes()
			},
			wantAdmit: false,
		},
		{
			name: "error in GR cluster rules resolve",
			globalRole: v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				Rules: []v1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
				InheritedClusterRoles: []string{"error"},
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
				state.rtCacheMock.EXPECT().Get("error").Return(nil, fmt.Errorf("server unavailable"))
			},
			wantAdmit: false,
			wantError: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			rtCacheMock := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
			state := testState{
				rtCacheMock: rtCacheMock,
			}
			if test.stateSetup != nil {
				test.stateSetup(state)
			}
			resolver, _ := validation.NewTestRuleResolver(nil, nil, []*v1.ClusterRole{&clusterRole}, []*v1.ClusterRoleBinding{&clusterRoleBinding})
			grbResolver := createBaseGRBResolver(ctrl, state.rtCacheMock)
			admitters := NewValidator(resolver, grbResolver).Admitters()
			assert.Len(t, admitters, 1)

			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation:       admissionv1.Create,
					UID:             "2",
					Kind:            globalRoleGVK,
					Resource:        globalRoleGVR,
					RequestKind:     &globalRoleGVK,
					RequestResource: &globalRoleGVR,
					Name:            "my-global-role",
					UserInfo:        authenicationv1.UserInfo{Username: "test-user", UID: ""},
					Object:          runtime.RawExtension{},
					OldObject:       runtime.RawExtension{},
				},
			}
			var err error
			req.Object.Raw, err = json.Marshal(test.globalRole)
			require.NoError(t, err, "Failed to marshal new GlobalRole while creating request")

			response, err := admitters[0].Admit(&req)
			if test.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.wantAdmit, response.Allowed)
			}
		})
	}
}

func TestValidateInheritedClusterRoles(t *testing.T) {
	t.Parallel()
	type testState struct {
		rtCacheMock *fake.MockNonNamespacedCacheInterface[*v3.RoleTemplate]
	}
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
	tests := []struct {
		name          string
		oldGlobalRole *v3.GlobalRole
		newGlobalRole *v3.GlobalRole
		operation     admissionv1.Operation
		stateSetup    func(testState)
		wantError     bool
		wantAdmit     bool
	}{
		{
			name: "new role not found roleTemplate",
			newGlobalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				Rules: []v1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
				InheritedClusterRoles: []string{"not-found"},
			},
			operation: admissionv1.Create,
			stateSetup: func(ts testState) {
				ts.rtCacheMock.EXPECT().Get("not-found").Return(nil, notFoundError)
			},
			wantAdmit: false,
			wantError: false,
		},
		{
			name: "new role misc. error roleTemplate",
			newGlobalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				Rules: []v1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
				InheritedClusterRoles: []string{"error"},
			},
			operation: admissionv1.Create,
			stateSetup: func(ts testState) {
				ts.rtCacheMock.EXPECT().Get("error").Return(nil, fmt.Errorf("server unavailable"))
			},
			wantError: true,
		},
		{
			name: "new role locked roleTemplate",
			newGlobalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				Rules: []v1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
				InheritedClusterRoles: []string{lockedRoleTemplate.Name},
			},
			operation: admissionv1.Create,
			stateSetup: func(ts testState) {
				ts.rtCacheMock.EXPECT().Get(lockedRoleTemplate.Name).Return(&lockedRoleTemplate, nil)
			},
			wantAdmit: false,
			wantError: false,
		},
		{
			name: "new role project context roleTemplate",
			newGlobalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				Rules: []v1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
				InheritedClusterRoles: []string{projectCtxRoleTemplate.Name},
			},
			operation: admissionv1.Create,
			stateSetup: func(ts testState) {
				ts.rtCacheMock.EXPECT().Get(projectCtxRoleTemplate.Name).Return(&projectCtxRoleTemplate, nil)
			},
			wantAdmit: false,
			wantError: false,
		},
		{
			name: "new role no context roleTemplate",
			newGlobalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				Rules: []v1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
				InheritedClusterRoles: []string{noCtxRoleTemplate.Name},
			},
			operation: admissionv1.Create,
			stateSetup: func(ts testState) {
				ts.rtCacheMock.EXPECT().Get(noCtxRoleTemplate.Name).Return(&noCtxRoleTemplate, nil)
			},
			wantAdmit: false,
			wantError: false,
		},
		{
			name: "old role invalid roleTemplates, new role valid",
			oldGlobalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				Rules: []v1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
				InheritedClusterRoles: []string{noCtxRoleTemplate.Name, projectCtxRoleTemplate.Name, lockedRoleTemplate.Name},
			},
			newGlobalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-gr",
				},
				Rules: []v1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"get"},
					},
				},
				InheritedClusterRoles: []string{validRoleTemplate.Name},
			},
			operation: admissionv1.Update,
			stateSetup: func(ts testState) {
				ts.rtCacheMock.EXPECT().Get(validRoleTemplate.Name).Return(&validRoleTemplate, nil).AnyTimes()
			},
			wantAdmit: true,
			wantError: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			rtCacheMock := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
			state := testState{
				rtCacheMock: rtCacheMock,
			}
			if test.stateSetup != nil {
				test.stateSetup(state)
			}
			resolver, _ := validation.NewTestRuleResolver(nil, nil, []*v1.ClusterRole{&clusterRole}, []*v1.ClusterRoleBinding{&clusterRoleBinding})
			grbResolver := createBaseGRBResolver(ctrl, state.rtCacheMock)
			admitters := NewValidator(resolver, grbResolver).Admitters()
			assert.Len(t, admitters, 1)

			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation:       test.operation,
					UID:             "2",
					Kind:            globalRoleGVK,
					Resource:        globalRoleGVR,
					RequestKind:     &globalRoleGVK,
					RequestResource: &globalRoleGVR,
					Name:            "my-global-role",
					UserInfo:        authenicationv1.UserInfo{Username: "test-user", UID: ""},
					Object:          runtime.RawExtension{},
					OldObject:       runtime.RawExtension{},
				},
			}
			var err error
			if test.oldGlobalRole != nil {
				req.OldObject.Raw, err = json.Marshal(test.oldGlobalRole)
				require.NoError(t, err, "Failed to marshal new GlobalRole while creating request")
			}
			req.Object.Raw, err = json.Marshal(test.newGlobalRole)
			require.NoError(t, err, "Failed to marshal new GlobalRole while creating request")

			response, err := admitters[0].Admit(&req)
			if test.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.wantAdmit, response.Allowed)
			}
		})
	}

}

func TestAllowMetaUpdate(t *testing.T) {
	t.Parallel()
	type testState struct {
		rtCacheMock *fake.MockNonNamespacedCacheInterface[*v3.RoleTemplate]
	}

	roleTemplate := v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-rt",
		},
		Context: "cluster",
		Rules: []v1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"*"},
			},
		},
	}
	tests := []struct {
		name          string
		newGlobalRole *v3.GlobalRole
		oldGlobalRole *v3.GlobalRole
		stateSetup    func(testState)
		wantError     bool
		wantAdmit     bool
	}{
		{
			name: "escalation in global + cluster rules, and invalid RT, but only meta changed",
			newGlobalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "meta-gr",
					Labels: map[string]string{
						"new-label": "just-added",
					},
				},
				Rules: []v1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"*"},
					},
				},
				InheritedClusterRoles: []string{roleTemplate.Name, "error"},
			},
			oldGlobalRole: &v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					Name: "meta-gr",
				},
				Rules: []v1.PolicyRule{
					{
						APIGroups: []string{""},
						Resources: []string{"pods"},
						Verbs:     []string{"*"},
					},
				},
				InheritedClusterRoles: []string{roleTemplate.Name, "error"},
			},
			wantAdmit: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			rtCacheMock := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
			state := testState{
				rtCacheMock: rtCacheMock,
			}
			if test.stateSetup != nil {
				test.stateSetup(state)
			}
			resolver, _ := validation.NewTestRuleResolver(nil, nil, []*v1.ClusterRole{&clusterRole}, []*v1.ClusterRoleBinding{&clusterRoleBinding})
			grbResolver := createBaseGRBResolver(ctrl, state.rtCacheMock)
			admitters := NewValidator(resolver, grbResolver).Admitters()
			assert.Len(t, admitters, 1)

			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation:       admissionv1.Update,
					UID:             "2",
					Kind:            globalRoleGVK,
					Resource:        globalRoleGVR,
					RequestKind:     &globalRoleGVK,
					RequestResource: &globalRoleGVR,
					Name:            "my-global-role",
					UserInfo:        authenicationv1.UserInfo{Username: "test-user", UID: ""},
					Object:          runtime.RawExtension{},
					OldObject:       runtime.RawExtension{},
				},
			}
			var err error
			req.Object.Raw, err = json.Marshal(test.newGlobalRole)
			require.NoError(t, err, "Failed to marshal new GlobalRole while creating request")

			req.OldObject.Raw, err = json.Marshal(test.oldGlobalRole)
			require.NoError(t, err, "Failed to marshal new GlobalRole while creating request")

			response, err := admitters[0].Admit(&req)
			if test.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.wantAdmit, response.Allowed)
			}
		})
	}
}

// createBaseGRBResolver creates a GRB resolver with some basic permissions setup for escalation checking
func createBaseGRBResolver(ctrl *gomock.Controller, rtCacheMock *fake.MockNonNamespacedCacheInterface[*v3.RoleTemplate]) *resolvers.GRBClusterRuleResolver {
	grCacheMock := fake.NewMockNonNamespacedCacheInterface[*v3.GlobalRole](ctrl)
	grbCacheMock := fake.NewMockNonNamespacedCacheInterface[*v3.GlobalRoleBinding](ctrl)
	grbs := []*v3.GlobalRoleBinding{&baseGRB}
	grbCacheMock.EXPECT().GetByIndex(gomock.Any(), resolvers.GetUserKey("test-user", "")).Return(grbs, nil).AnyTimes()
	grbCacheMock.EXPECT().AddIndexer(gomock.Any(), gomock.Any()).AnyTimes()
	grCacheMock.EXPECT().Get(baseGR.Name).Return(&baseGR, nil).AnyTimes()
	rtCacheMock.EXPECT().Get(baseRT.Name).Return(&baseRT, nil).AnyTimes()

	grResolver := auth.NewGlobalRoleResolver(auth.NewRoleTemplateResolver(rtCacheMock, nil), grCacheMock)
	return resolvers.NewGRBClusterRuleResolver(grbCacheMock, grResolver)
}
