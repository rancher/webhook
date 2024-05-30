package feature

import (
	"encoding/json"
	"testing"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authenicationv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	featureGVR = metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "features"}
	featureGVK = metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "Feature"}
)

func TestFeatureValueValid(t *testing.T) {
	type testState struct {
		authorizationRuleResolverMock *mocks.MockAuthorizationRuleResolver
	}
	ctrl := gomock.NewController(t)

	t.Parallel()
	tests := []struct {
		name       string
		newFeature v3.Feature
		oldFeature v3.Feature
		wantError  bool
		wantAdmit  bool
		stateSetup func(state testState)
	}{
		{
			name: "new feature locked with spec value changed",
			oldFeature: v3.Feature{
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(true),
				},
			},
			newFeature: v3.Feature{
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(false),
				},
				Status: v3.FeatureStatus{
					LockedValue: admission.Ptr(true),
				},
			},
			wantAdmit: false,
		},
		{
			name: "new feature not locked with spec value changed",
			oldFeature: v3.Feature{
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(true),
				},
			},
			newFeature: v3.Feature{
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(false),
				},
				Status: v3.FeatureStatus{
					LockedValue: admission.Ptr(false),
				},
			},
			wantAdmit: true,
		},
		{
			name: "new feature not locked with spec value unchanged",
			oldFeature: v3.Feature{
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(true),
				},
			},
			newFeature: v3.Feature{
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(true),
				},
				Status: v3.FeatureStatus{
					LockedValue: admission.Ptr(true),
				},
			},
			wantAdmit: true,
		},
		{
			name:       "new feature lock is nil",
			oldFeature: v3.Feature{},
			newFeature: v3.Feature{},
			wantAdmit:  true,
		},
		{
			name:       "both feature specs are nil",
			oldFeature: v3.Feature{},
			newFeature: v3.Feature{
				Status: v3.FeatureStatus{
					LockedValue: admission.Ptr(true),
				},
			},
			wantAdmit: true,
		},
		{
			name: "external rules feature can be changed by admins",
			oldFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(true),
				},
			},
			newFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(false),
				},
			},
			stateSetup: func(state testState) {
				adminRules := []rbacv1.PolicyRule{
					{
						Verbs:     []string{"*"},
						APIGroups: []string{"*"},
						Resources: []string{"*"},
					},
				}
				state.authorizationRuleResolverMock.EXPECT().RulesFor(gomock.Any(), gomock.Any()).Return(adminRules, nil)
			},
			wantAdmit: true,
		},
		{
			name: "external rules feature can't be enabled by users with update permissions",
			oldFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(false),
				},
			},
			newFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(true),
				},
			},
			stateSetup: func(state testState) {
				adminRules := []rbacv1.PolicyRule{
					{
						Verbs:     []string{"update"},
						APIGroups: []string{"management.cattle.io"},
						Resources: []string{"features"},
					},
				}
				state.authorizationRuleResolverMock.EXPECT().RulesFor(gomock.Any(), gomock.Any()).Return(adminRules, nil)
			},
			wantAdmit: false,
		},
		{
			name: "external rules feature can't be disabled by users with update permissions",
			oldFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(true),
				},
			},
			newFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(false),
				},
			},
			stateSetup: func(state testState) {
				adminRules := []rbacv1.PolicyRule{
					{
						Verbs:     []string{"update"},
						APIGroups: []string{"management.cattle.io"},
						Resources: []string{"features"},
					},
				}
				state.authorizationRuleResolverMock.EXPECT().RulesFor(gomock.Any(), gomock.Any()).Return(adminRules, nil)
			},
			wantAdmit: false,
		},
		{
			name: "external rules feature can't be set to nil by users with update permissions",
			oldFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(true),
				},
			},
			newFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: nil,
				},
			},
			stateSetup: func(state testState) {
				adminRules := []rbacv1.PolicyRule{
					{
						Verbs:     []string{"update"},
						APIGroups: []string{"management.cattle.io"},
						Resources: []string{"features"},
					},
				}
				state.authorizationRuleResolverMock.EXPECT().RulesFor(gomock.Any(), gomock.Any()).Return(adminRules, nil)
			},
			wantAdmit: false,
		},
		{
			name: "external rules feature can be enabled for users with security-enable (RA)",
			oldFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(false),
				},
			},
			newFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(true),
				},
			},
			stateSetup: func(state testState) {
				state.authorizationRuleResolverMock.EXPECT().RulesFor(gomock.Any(), gomock.Any()).Return([]rbacv1.PolicyRule{
					{
						Verbs:         []string{"security-enable"},
						APIGroups:     []string{"management.cattle.io"},
						Resources:     []string{"features"},
						ResourceNames: []string{"external-rules"},
					},
				}, nil)
			},
			wantAdmit: true,
		},
		{
			name: "external rules feature can't be disabled for users with security-enable (RA)",
			oldFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(true),
				},
			},
			newFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(false),
				},
			},
			stateSetup: func(state testState) {
				state.authorizationRuleResolverMock.EXPECT().RulesFor(gomock.Any(), gomock.Any()).Return([]rbacv1.PolicyRule{
					{
						Verbs:         []string{"security-enable", "update"},
						APIGroups:     []string{"management.cattle.io"},
						Resources:     []string{"features"},
						ResourceNames: []string{"external-rules"},
					},
				}, nil)
			},
			wantAdmit: false,
		},
		{
			name: "external rules feature can be enabled with default value for users with security-enable (RA)",
			oldFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: nil,
				},
				Status: v3.FeatureStatus{
					Default: false,
				},
			},
			newFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(true),
				},
			},
			stateSetup: func(state testState) {
				state.authorizationRuleResolverMock.EXPECT().RulesFor(gomock.Any(), gomock.Any()).Return([]rbacv1.PolicyRule{
					{
						Verbs:         []string{"security-enable"},
						APIGroups:     []string{"management.cattle.io"},
						Resources:     []string{"features"},
						ResourceNames: []string{"external-rules"},
					},
				}, nil)
			},
			wantAdmit: true,
		},
		{
			name: "external rules feature can't be disabled for users with security-enable (RA)",
			oldFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: nil,
				},
				Status: v3.FeatureStatus{
					Default: true,
				},
			},
			newFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(false),
				},
			},
			stateSetup: func(state testState) {
				state.authorizationRuleResolverMock.EXPECT().RulesFor(gomock.Any(), gomock.Any()).Return([]rbacv1.PolicyRule{
					{
						Verbs:         []string{"security-enable", "update"},
						APIGroups:     []string{"management.cattle.io"},
						Resources:     []string{"features"},
						ResourceNames: []string{"external-rules"},
					},
				}, nil)
			},
			wantAdmit: false,
		},
		{
			name: "external rules feature can't be set to nil for users with security-enable (RA)",
			oldFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(true),
				},
			},
			newFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: nil,
				},
			},
			stateSetup: func(state testState) {
				state.authorizationRuleResolverMock.EXPECT().RulesFor(gomock.Any(), gomock.Any()).Return([]rbacv1.PolicyRule{
					{
						Verbs:         []string{"security-enable", "update"},
						APIGroups:     []string{"management.cattle.io"},
						Resources:     []string{"features"},
						ResourceNames: []string{"external-rules"},
					},
				}, nil)
			},
			wantAdmit: false,
		},
		{
			name: "external rules feature can be modified if the value doesn't change",
			oldFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(true),
				},
			},
			newFeature: v3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: auth.ExternalRulesFeature,
					Annotations: map[string]string{
						"test-annotation": "test-value",
					},
				},
				Spec: v3.FeatureSpec{
					Value: admission.Ptr(true),
				},
			},
			wantAdmit: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			authorizationRuleResolverMock := mocks.NewMockAuthorizationRuleResolver(ctrl)
			state := testState{
				authorizationRuleResolverMock: authorizationRuleResolverMock,
			}
			if test.stateSetup != nil {
				test.stateSetup(state)
			}
			admitters := NewValidator(state.authorizationRuleResolverMock).Admitters()
			assert.Len(t, admitters, 1)

			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID:             "2",
					Kind:            featureGVK,
					Resource:        featureGVR,
					RequestKind:     &featureGVK,
					RequestResource: &featureGVR,
					Name:            "my-feature",
					Operation:       admissionv1.Update,
					UserInfo:        authenicationv1.UserInfo{Username: "test-user", UID: ""},
					Object:          runtime.RawExtension{},
					OldObject:       runtime.RawExtension{},
				},
			}
			var err error
			req.Object.Raw, err = json.Marshal(test.newFeature)
			assert.NoError(t, err, "Failed to marshal new Feature while creating request")
			req.OldObject.Raw, err = json.Marshal(test.oldFeature)
			assert.NoError(t, err, "Failed to marshal old Feature while creating request")

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
	admitters := NewValidator(nil).Admitters()
	assert.Len(t, admitters, 1)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:             "2",
			Kind:            featureGVK,
			Resource:        featureGVR,
			RequestKind:     &featureGVK,
			RequestResource: &featureGVR,
			Name:            "my-feature",
			Operation:       admissionv1.Update,
			UserInfo:        authenicationv1.UserInfo{Username: "test-user", UID: ""},
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
	}

	_, err := admitters[0].Admit(&req)
	require.Error(t, err)
}
