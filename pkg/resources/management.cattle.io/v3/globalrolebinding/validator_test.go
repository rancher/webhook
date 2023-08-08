package globalrolebinding_test

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
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/globalrolebinding"
	"github.com/rancher/wrangler/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

var (
	globalRoleBindingGVR = metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "globalRoleBindings"}
	globalRoleBindingGVK = metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "GlobalRoleBinding"}
	clusterRole          = rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-cr",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "configmaps"},
				Verbs:     []string{"get"},
			},
		},
	}
	clusterRoleBinding = rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-crb",
		},
		RoleRef: rbacv1.RoleRef{
			APIGroup: "rbac.authorization.k8s.io",
			Kind:     "ClusterRole",
			Name:     clusterRole.Name,
		},
		Subjects: []rbacv1.Subject{
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
		Rules: []rbacv1.PolicyRule{
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
		Rules: []rbacv1.PolicyRule{
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
	escalationRT = v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "escalation-rt",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"*"},
			},
		},
	}

	lockedRT = v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			Name: "locked-rt",
		},
		Locked: true,
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"configmaps"},
				Verbs:     []string{"get"},
			},
		},
	}
	allowedGR = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "allowed-gr",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
		},
	}
	escalationRulesGR = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "allowed-gr",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"*"},
			},
		},
	}
	escalationClusterGR = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "allowed-gr",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
		},
		InheritedClusterRoles: []string{
			escalationRT.Name,
		},
	}
	lockedRoleGR = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "locked-gr",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
		},
		InheritedClusterRoles: []string{
			lockedRT.Name,
		},
	}
	notFoundRoleGR = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "not-found-gr",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
		},
		InheritedClusterRoles: []string{
			"not-found",
		},
	}
	errorRoleGR = v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "error-gr",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get"},
			},
		},
		InheritedClusterRoles: []string{
			"error",
		},
	}
)

func TestAdmit(t *testing.T) {
	type testState struct {
		rtCacheMock  *fake.MockNonNamespacedCacheInterface[*v3.RoleTemplate]
		grCacheMock  *fake.MockNonNamespacedCacheInterface[*v3.GlobalRole]
		grbCacheMock *fake.MockNonNamespacedCacheInterface[*v3.GlobalRoleBinding]
	}

	type testCase struct {
		name                 string
		globalRoleBinding    *v3.GlobalRoleBinding
		oldGlobalRoleBinding *v3.GlobalRoleBinding
		operation            admissionv1.Operation
		stateSetup           func(testState)
		wantError            bool
		wantAdmit            bool
	}

	tests := []testCase{
		{
			name: "test create global role not found",
			globalRoleBinding: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
				UserName:       "test-user",
				GlobalRoleName: "not-found",
			},
			operation: admissionv1.Create,
			stateSetup: func(ts testState) {
				notFoundError := apierrors.NewNotFound(schema.GroupResource{
					Group:    "management.cattle.io",
					Resource: "globalroles",
				}, "not-found")
				ts.grCacheMock.EXPECT().Get("not-found").Return(nil, notFoundError)
			},
			wantError: false,
			wantAdmit: false,
		},

		{
			name: "test delete global role not found",
			globalRoleBinding: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
				UserName:       "test-user",
				GlobalRoleName: "not-found",
			},
			operation: admissionv1.Delete,
			stateSetup: func(ts testState) {
				notFoundError := apierrors.NewNotFound(schema.GroupResource{
					Group:    "management.cattle.io",
					Resource: "globalroles",
				}, "not-found")
				ts.grCacheMock.EXPECT().Get("not-found").Return(nil, notFoundError)
			},
			wantError: false,
			wantAdmit: true,
		},
		{
			name: "test update gr not found, grb not deleting",
			globalRoleBinding: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
				UserName:       "test-user",
				GlobalRoleName: "not-found",
			},
			operation: admissionv1.Update,
			stateSetup: func(ts testState) {
				notFoundError := apierrors.NewNotFound(schema.GroupResource{
					Group:    "management.cattle.io",
					Resource: "globalroles",
				}, "not-found")
				ts.grCacheMock.EXPECT().Get("not-found").Return(nil, notFoundError)
			},
			wantError: false,
			wantAdmit: false,
		},
		{
			name: "test update gr not found, grb deleting",
			globalRoleBinding: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name:              "test-grb",
					DeletionTimestamp: &metav1.Time{Time: time.Now()},
				},
				UserName:       "test-user",
				GlobalRoleName: "not-found",
			},
			operation: admissionv1.Update,
			stateSetup: func(ts testState) {
				notFoundError := apierrors.NewNotFound(schema.GroupResource{
					Group:    "management.cattle.io",
					Resource: "globalroles",
				}, "not-found")
				ts.grCacheMock.EXPECT().Get("not-found").Return(nil, notFoundError)
			},
			wantError: false,
			wantAdmit: true,
		},
		{
			name: "test create gr refers to locked RT",
			globalRoleBinding: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
				UserName:       "test-user",
				GlobalRoleName: lockedRoleGR.Name,
			},
			operation: admissionv1.Create,
			stateSetup: func(ts testState) {
				ts.grCacheMock.EXPECT().Get(lockedRoleGR.Name).Return(&lockedRoleGR, nil)
				ts.rtCacheMock.EXPECT().Get(lockedRT.Name).Return(&lockedRT, nil)
			},
			wantError: false,
			wantAdmit: false,
		},
		{
			name: "test create gr refers to not found RT",
			globalRoleBinding: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
				UserName:       "test-user",
				GlobalRoleName: notFoundRoleGR.Name,
			},
			operation: admissionv1.Create,
			stateSetup: func(ts testState) {
				notFoundError := apierrors.NewNotFound(schema.GroupResource{
					Group:    "management.cattle.io",
					Resource: "roletemplates",
				}, "not-found")
				ts.grCacheMock.EXPECT().Get(notFoundRoleGR.Name).Return(&notFoundRoleGR, nil)
				ts.rtCacheMock.EXPECT().Get("not-found").Return(nil, notFoundError)
			},
			wantError: false,
			wantAdmit: false,
		},
		{
			name: "test create gr refers to RT misc error",
			globalRoleBinding: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
				UserName:       "test-user",
				GlobalRoleName: errorRoleGR.Name,
			},
			operation: admissionv1.Create,
			stateSetup: func(ts testState) {
				ts.grCacheMock.EXPECT().Get(errorRoleGR.Name).Return(&errorRoleGR, nil)
				ts.rtCacheMock.EXPECT().Get("error").Return(nil, fmt.Errorf("server not available"))
			},
			wantError: true,
		},
		{
			name: "test update gr refers to RT misc error",
			globalRoleBinding: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
				UserName:       "test-user",
				GlobalRoleName: errorRoleGR.Name,
			},
			operation: admissionv1.Update,
			stateSetup: func(ts testState) {
				ts.grCacheMock.EXPECT().Get(errorRoleGR.Name).Return(&errorRoleGR, nil)
				ts.rtCacheMock.EXPECT().Get("error").Return(nil, fmt.Errorf("server not available"))
			},
			wantError: true,
		},
		{
			name: "test update gr refers to locked RT",
			globalRoleBinding: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
				UserName:       "test-user",
				GlobalRoleName: lockedRoleGR.Name,
			},
			operation: admissionv1.Update,
			stateSetup: func(ts testState) {
				ts.grCacheMock.EXPECT().Get(lockedRoleGR.Name).Return(&lockedRoleGR, nil)
				ts.rtCacheMock.EXPECT().Get(lockedRT.Name).Return(&lockedRT, nil)
			},
			wantError: false,
			wantAdmit: true,
		},
		{
			name: "test update meta-only changed",
			globalRoleBinding: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
					Labels: map[string]string{
						"updated": "yes",
					},
				},
				UserName:       "test-user",
				GlobalRoleName: "error",
			},
			oldGlobalRoleBinding: &v3.GlobalRoleBinding{
				ObjectMeta: metav1.ObjectMeta{
					Name: "test-grb",
				},
				UserName:       "test-user",
				GlobalRoleName: "error",
			},
			operation: admissionv1.Update,
			wantError: false,
			wantAdmit: true,
		},
	}

	// some tests work the same way across all operations - they are added here to avoid duplicate code
	operations := []admissionv1.Operation{admissionv1.Create, admissionv1.Update, admissionv1.Delete}
	for _, operation := range operations {
		commonTests := []testCase{
			{
				name: fmt.Sprintf("test %s no escalation", operation),
				globalRoleBinding: &v3.GlobalRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-grb",
					},
					UserName:       "test-user",
					GlobalRoleName: allowedGR.Name,
				},
				operation: operation,
				stateSetup: func(ts testState) {
					ts.grCacheMock.EXPECT().Get(allowedGR.Name).Return(&allowedGR, nil)
				},
				wantAdmit: true,
			},
			{
				name: fmt.Sprintf("test %s escalation in GR rules", operation),
				globalRoleBinding: &v3.GlobalRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-grb",
					},
					UserName:       "test-user",
					GlobalRoleName: escalationRulesGR.Name,
				},
				operation: operation,
				stateSetup: func(ts testState) {
					ts.grCacheMock.EXPECT().Get(escalationRulesGR.Name).Return(&escalationRulesGR, nil)
				},
				wantAdmit: false,
			},
			{
				name: fmt.Sprintf("test %s escalation in GR Cluster Roles", operation),
				globalRoleBinding: &v3.GlobalRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-grb",
					},
					UserName:       "test-user",
					GlobalRoleName: escalationClusterGR.Name,
				},
				operation: operation,
				stateSetup: func(ts testState) {
					ts.grCacheMock.EXPECT().Get(escalationClusterGR.Name).Return(&escalationClusterGR, nil)
					ts.rtCacheMock.EXPECT().Get(escalationRT.Name).Return(&escalationRT, nil).AnyTimes()
				},
				wantAdmit: false,
			},
			{
				name: fmt.Sprintf("test %s not found error resolving rules", operation),
				globalRoleBinding: &v3.GlobalRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-grb",
					},
					UserName:       "test-user",
					GlobalRoleName: notFoundRoleGR.Name,
				},
				operation: operation,
				stateSetup: func(ts testState) {
					notFoundError := apierrors.NewNotFound(schema.GroupResource{
						Group:    "management.cattle.io",
						Resource: "roletemplates",
					}, "not-found")
					ts.grCacheMock.EXPECT().Get(notFoundRoleGR.Name).Return(&notFoundRoleGR, nil)
					ts.rtCacheMock.EXPECT().Get("not-found").Return(nil, notFoundError)
				},
				wantAdmit: false,
			},
			{
				name: fmt.Sprintf("test %s error getting global role", operation),
				globalRoleBinding: &v3.GlobalRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name: "test-grb",
					},
					UserName:       "test-user",
					GlobalRoleName: "error",
				},
				operation: operation,
				stateSetup: func(ts testState) {
					ts.grCacheMock.EXPECT().Get("error").Return(nil, fmt.Errorf("server unavailable"))
				},
				wantError: true,
			},

			{
				name:              fmt.Sprintf("test %s decode error", operation),
				globalRoleBinding: nil,
				operation:         operation,
				wantAdmit:         false,
				wantError:         true,
			},
		}
		tests = append(tests, commonTests...)
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			rtCacheMock := fake.NewMockNonNamespacedCacheInterface[*v3.RoleTemplate](ctrl)
			grCacheMock := fake.NewMockNonNamespacedCacheInterface[*v3.GlobalRole](ctrl)
			grbCacheMock := fake.NewMockNonNamespacedCacheInterface[*v3.GlobalRoleBinding](ctrl)

			grbs := []*v3.GlobalRoleBinding{&baseGRB}
			grbCacheMock.EXPECT().GetByIndex(gomock.Any(), resolvers.GetUserKey("test-user", "")).Return(grbs, nil).AnyTimes()
			grbCacheMock.EXPECT().AddIndexer(gomock.Any(), gomock.Any()).AnyTimes()
			grCacheMock.EXPECT().Get(baseGR.Name).Return(&baseGR, nil).AnyTimes()
			rtCacheMock.EXPECT().Get(baseRT.Name).Return(&baseRT, nil).AnyTimes()
			state := testState{
				rtCacheMock:  rtCacheMock,
				grCacheMock:  grCacheMock,
				grbCacheMock: grbCacheMock,
			}
			if test.stateSetup != nil {
				test.stateSetup(state)
			}
			resolver, _ := validation.NewTestRuleResolver(nil, nil, []*rbacv1.ClusterRole{&clusterRole}, []*rbacv1.ClusterRoleBinding{&clusterRoleBinding})
			grResolver := auth.NewGlobalRoleResolver(auth.NewRoleTemplateResolver(state.rtCacheMock, nil), state.grCacheMock)
			grbResolver := resolvers.NewGRBClusterRuleResolver(state.grbCacheMock, grResolver)
			admitters := globalrolebinding.NewValidator(resolver, grbResolver).Admitters()
			require.Len(t, admitters, 1)

			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation:       test.operation,
					UID:             "2",
					Kind:            globalRoleBindingGVK,
					Resource:        globalRoleBindingGVR,
					RequestKind:     &globalRoleBindingGVK,
					RequestResource: &globalRoleBindingGVR,
					Name:            "test-grb",
					UserInfo:        authenticationv1.UserInfo{Username: "test-user", UID: ""},
					Object:          runtime.RawExtension{},
					OldObject:       runtime.RawExtension{},
				},
			}
			if test.globalRoleBinding != nil {
				var err error
				switch test.operation {
				case admissionv1.Create:
					fallthrough
				case admissionv1.Update:
					req.Object.Raw, err = json.Marshal(test.globalRoleBinding)
					require.NoError(t, err, "Failed to marshal new GlobalRole while creating request")
					if test.oldGlobalRoleBinding != nil {
						req.OldObject.Raw, err = json.Marshal(test.oldGlobalRoleBinding)
					} else {
						req.OldObject.Raw, err = json.Marshal(&v3.GlobalRoleBinding{})
					}
				case admissionv1.Delete:
					req.OldObject.Raw, err = json.Marshal(test.globalRoleBinding)
				}
				require.NoError(t, err, "Failed to marshal GlobalRole while creating request")
			}

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
