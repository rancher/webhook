package setting_test

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/setting"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type SettingSuite struct {
	suite.Suite
}

func TestUserRetentionSettingsValidation(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(SettingSuite))
}

var (
	gvk = metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "Setting"}
	gvr = metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "settings"}
)

func (s *SettingSuite) TestValidateUserRetentionSettingsOnUpdate() {
	s.validateUserRetentionSettings(v1.Update)
}

func (s *SettingSuite) TestValidateUserRetentionSettingsOnCreate() {
	s.validateUserRetentionSettings(v1.Create)
}

func (s *SettingSuite) validateUserRetentionSettings(op v1.Operation) {
	tests := []struct {
		setting           string
		value             string
		userSessionTTL    string
		userSessionTTLErr error
		allowed           bool
	}{
		{
			setting: setting.DisableInactiveUserAfter,
			value:   "",
			allowed: true,
		},
		{
			setting: setting.DeleteInactiveUserAfter,
			value:   "",
			allowed: true,
		},
		{
			setting: setting.UserLastLoginDefault,
			value:   "",
			allowed: true,
		},
		{
			setting: setting.UserRetentionCron,
			value:   "",
			allowed: true,
		},
		{
			setting:        setting.DisableInactiveUserAfter,
			userSessionTTL: "960",
			value:          "16h1s",
			allowed:        true,
		},
		{
			setting:        setting.DeleteInactiveUserAfter,
			userSessionTTL: "960",
			value:          setting.MinDeleteInactiveUserAfter.String(),
			allowed:        true,
		},
		{
			setting: setting.UserLastLoginDefault,
			value:   "2024-01-08T00:00:00Z",
			allowed: true,
		},
		{
			setting: setting.UserRetentionCron,
			value:   "* * * * *",
			allowed: true,
		},
		{
			setting:        setting.DisableInactiveUserAfter,
			userSessionTTL: "foo",
			value:          "15h",
			allowed:        true,
		},
		{
			setting:        setting.DeleteInactiveUserAfter,
			userSessionTTL: "foo",
			value:          setting.MinDeleteInactiveUserAfter.String(),
			allowed:        true,
		},
		{
			setting:           setting.DisableInactiveUserAfter,
			userSessionTTLErr: errors.New("some error"),
			value:             "16h", // 960 minutes.
			allowed:           true,
		},
		{
			setting:           setting.DeleteInactiveUserAfter,
			userSessionTTLErr: errors.New("some error"),
			value:             setting.MinDeleteInactiveUserAfter.String(),
			allowed:           true,
		},
		{
			setting:        setting.DisableInactiveUserAfter,
			userSessionTTL: "960",
			value:          "15h59m59s",
		},
		{
			setting:        setting.DeleteInactiveUserAfter,
			userSessionTTL: strconv.Itoa(int((setting.MinDeleteInactiveUserAfter + time.Hour).Minutes())),
			value:          setting.MinDeleteInactiveUserAfter.String(),
		},
		{
			setting: setting.DisableInactiveUserAfter,
			value:   "1w",
		},
		{
			setting: setting.DeleteInactiveUserAfter,
			value:   "2d",
		},
		{
			setting: setting.UserLastLoginDefault,
			value:   "foo",
		},
		{
			setting: setting.UserRetentionCron,
			value:   "* * * * * *",
		},
		{
			setting: setting.DisableInactiveUserAfter,
			value:   "-1h",
		},
		{
			setting: setting.DeleteInactiveUserAfter,
			value:   "-1h",
		},
		{
			setting: setting.DeleteInactiveUserAfter,
			value:   (setting.MinDeleteInactiveUserAfter - time.Second).String(),
		},
	}

	for _, test := range tests {
		test := test
		name := test.setting + "_" + test.value + "_" + test.userSessionTTL
		s.T().Run(name, func(t *testing.T) {
			t.Parallel()

			ctrl := gomock.NewController(t)
			settingCache := fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)

			getUserSessionTTLCalledTimes := 0
			if test.userSessionTTL != "" || test.userSessionTTLErr != nil {
				getUserSessionTTLCalledTimes = 1
			}

			settingCache.EXPECT().Get(setting.AuthUserSessionTTLMinutes).DoAndReturn(func(string) (*v3.Setting, error) {
				if test.userSessionTTLErr != nil {
					return nil, test.userSessionTTLErr
				}
				return &v3.Setting{
					Default: test.userSessionTTL,
				}, nil
			}).Times(getUserSessionTTLCalledTimes)

			oldObjRaw, err := json.Marshal(v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: test.setting,
				},
			})
			assert.NoError(t, err, "failed to marshal old Setting")

			objRaw, err := json.Marshal(v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: test.setting,
				},
				Value: test.value,
			})
			assert.NoError(t, err, "failed to marshal Setting")

			validator := setting.NewValidator(nil, settingCache)
			require.Len(t, validator.Admitters(), 1)

			resp, err := validator.Admitters()[0].Admit(newRequest(op, objRaw, oldObjRaw))
			require.NoError(t, err)
			assert.Equal(t, test.allowed, resp.Allowed)
		})
	}
}

func (s *SettingSuite) TestValidateAuthUserSessionTTLMinutesOnUpdate() {
	s.validateAuthUserSessionTTLMinutes(v1.Update)
}

func (s *SettingSuite) TestValidateAuthUserSessionTTLMinutesOnCreate() {
	s.validateAuthUserSessionTTLMinutes(v1.Create)
}

func (s *SettingSuite) validateAuthUserSessionTTLMinutes(op v1.Operation) {
	tests := []struct {
		desc            string
		value           string
		disableAfter    string
		disableAfterErr error
		deleteAfter     string
		deleteAfterErr  error
		allowed         bool
	}{
		{
			desc:    "empty",
			allowed: true,
		},
		{
			desc:    "reasonable value",
			value:   "960",
			allowed: true,
		},
		{
			desc:         "less than disable-inactive-user-after",
			value:        "960", // 16h
			disableAfter: "168h",
			allowed:      true,
		},
		{
			desc:        "less than delete-inactive-user-after",
			value:       "960", // 16h
			deleteAfter: "336h",
			allowed:     true,
		},
		{
			desc:         "less than both",
			value:        "960", // 16h
			disableAfter: "168h",
			deleteAfter:  "336h",
			allowed:      true,
		},
		{
			desc:         "can't parse disable-inactive-user-after",
			value:        "960", // 16h
			disableAfter: "foo",
			allowed:      true,
		},
		{
			desc:        "can't parse delete-inactive-user-after",
			value:       "960", // 16h
			deleteAfter: "foo",
			allowed:     true,
		},
		{
			desc:            "error getting disable-inactive-user-after",
			value:           "960", // 16h
			disableAfterErr: errors.New("some error"),
			allowed:         true,
		},
		{
			desc:           "error getting delete-inactive-user-after",
			value:          "960", // 16h
			deleteAfterErr: errors.New("some error"),
			allowed:        true,
		},
		{
			desc:         "negative disable-inactive-user-after",
			value:        "960", // 16h
			disableAfter: "-1h",
			allowed:      true,
		},
		{
			desc:        "negative delete-inactive-user-after",
			value:       "960", // 16h
			deleteAfter: "-1h",
			allowed:     true,
		},
		{
			desc:  "can't parse value",
			value: "foo",
		},
		{
			desc:  "negative value",
			value: "-960",
		},
		{
			desc:         "greater than disable-inactive-user-after",
			value:        "960", // 16h
			disableAfter: "15h",
		},
		{
			desc:        "greater than delete-inactive-user-after",
			value:       "960", // 16h
			deleteAfter: "15h",
		},
		{
			desc:         "greater than both",
			value:        "960", // 16h
			disableAfter: "15h",
			deleteAfter:  "15h",
		},
	}

	for _, test := range tests {
		test := test
		t := s.T()
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var settingGetCalledTimes int
			ctrl := gomock.NewController(t)
			settingCache := fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)
			settingCache.EXPECT().Get(gomock.Any()).DoAndReturn(func(name string) (*v3.Setting, error) {
				var value string
				switch name {
				case setting.DisableInactiveUserAfter:
					if test.disableAfterErr != nil {
						return nil, test.disableAfterErr
					}
					value = test.disableAfter
				case setting.DeleteInactiveUserAfter:
					if test.deleteAfterErr != nil {
						return nil, test.deleteAfterErr
					}
					value = test.deleteAfter
				default:
					t.Errorf("unexpected call to get setting %s", name)
				}

				setting := &v3.Setting{
					ObjectMeta: metav1.ObjectMeta{Name: name},
				}

				// Make sure we use the effective value of the setting.
				if settingGetCalledTimes%2 == 0 {
					setting.Value = value
				} else {
					setting.Default = value
				}

				return setting, nil
			}).AnyTimes()

			oldObjRaw, err := json.Marshal(v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AuthUserSessionTTLMinutes,
				},
			})
			assert.NoError(t, err, "failed to marshal old Setting")

			objRaw, err := json.Marshal(v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AuthUserSessionTTLMinutes,
				},
				Value: test.value,
			})
			assert.NoError(t, err, "failed to marshal Setting")

			validator := setting.NewValidator(nil, settingCache)
			require.Len(t, validator.Admitters(), 1)

			resp, err := validator.Admitters()[0].Admit(newRequest(op, objRaw, oldObjRaw))
			require.NoError(t, err)
			assert.Equal(t, test.allowed, resp.Allowed)

		})
	}
}

func (s *SettingSuite) TestValidatingWebhookFailurePolicy() {
	t := s.T()
	validator := setting.NewValidator(nil, nil)

	webhook := validator.ValidatingWebhook(admissionregistrationv1.WebhookClientConfig{})
	require.Len(t, webhook, 1)
	ignorePolicy := admissionregistrationv1.Ignore
	require.Equal(t, &ignorePolicy, webhook[0].FailurePolicy)
}

func newRequest(op v1.Operation, obj, oldObj []byte) *admission.Request {
	return &admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Operation:       op,
			UserInfo:        authenticationv1.UserInfo{Username: "foo", UID: ""},
			Object:          runtime.RawExtension{Raw: obj},
			OldObject:       runtime.RawExtension{Raw: oldObj},
		},
		Context: context.Background(),
	}
}

func TestValidateAgentTLSMode(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		oldSetting         v3.Setting
		newSetting         v3.Setting
		operation          v1.Operation
		clusters           []*v3.Cluster
		clusterListerFails bool
		allowed            bool
	}{
		"create allowed for system store": {
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Default: "system-store",
			},
			operation: v1.Create,
			allowed:   true,
		},
		"create allowed for strict": {
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Default: "strict",
			},
			operation: v1.Create,
			allowed:   true,
		},
		"update forbidden due to missing status": {
			oldSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Value: "system-store",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Value: "strict",
			},
			clusters: []*v3.Cluster{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster-1",
					},
					Status: v3.ClusterStatus{
						Conditions: []v3.ClusterCondition{
							{
								Type:   "AgentTlsStrictCheck",
								Status: "True",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster-2",
					},
				},
			},
			operation: v1.Update,
			allowed:   false,
		},
		"update allowed without cluster status but with force annotation": {
			oldSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Default: "system-store",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
					Annotations: map[string]string{
						"cattle.io/force": "true",
					},
				},
				Default: "strict",
			},
			clusters: []*v3.Cluster{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster-1",
					},
					Status: v3.ClusterStatus{
						Conditions: []v3.ClusterCondition{
							{
								Type:   "AgentTlsStrictCheck",
								Status: "True",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster-2",
					},
					Status: v3.ClusterStatus{
						Conditions: []v3.ClusterCondition{
							{
								Type:   "Foo",
								Status: "True",
							},
						},
					},
				},
			},
			operation: v1.Update,
			allowed:   true,
		},
		"update forbidden without cluster status and non-true force annotation": {
			oldSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Default: "system-store",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
					Annotations: map[string]string{
						"cattle.io/force": "false",
					},
				},
				Default: "strict",
			},
			clusters: []*v3.Cluster{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster-1",
					},
					Status: v3.ClusterStatus{
						Conditions: []v3.ClusterCondition{
							{
								Type:   "AgentTlsStrictCheck",
								Status: "False",
							},
						},
					},
				},
			},
			operation: v1.Update,
			allowed:   false,
		},
		"update allowed with cluster status and force annotation": {
			oldSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Value: "system-store",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
					Annotations: map[string]string{
						"cattle.io/force": "true",
					},
				},
				Value: "strict",
			},
			clusters: []*v3.Cluster{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster-1",
					},
					Status: v3.ClusterStatus{
						Conditions: []v3.ClusterCondition{
							{
								Type:   "AgentTlsStrictCheck",
								Status: "True",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster-2",
					},
					Status: v3.ClusterStatus{
						Conditions: []v3.ClusterCondition{
							{
								Type:   "AgentTlsStrictCheck",
								Status: "True",
							},
						},
					},
				},
			},
			operation: v1.Update,
			allowed:   true,
		},
		"update allowed from strict to system store": {
			oldSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Default: "strict",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Default: "system-store",
			},
			operation: v1.Update,
			allowed:   true,
		},
		"update allowed from system store to strict": {
			oldSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Default: "system-store",
				Value:   "system-store",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Default: "strict",
				Value:   "strict",
			},
			clusters: []*v3.Cluster{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "local",
					},
					Status: v3.ClusterStatus{
						Conditions: []v3.ClusterCondition{
							{
								Type:   "AgentTlsStrictCheck",
								Status: "False",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster-1",
					},
					Status: v3.ClusterStatus{
						Conditions: []v3.ClusterCondition{
							{
								Type:   "AgentTlsStrictCheck",
								Status: "True",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster-2",
					},
					Status: v3.ClusterStatus{
						Conditions: []v3.ClusterCondition{
							{
								Type:   "AgentTlsStrictCheck",
								Status: "True",
							},
						},
					},
				},
			},
			operation: v1.Update,
			allowed:   true,
		},
		"update allowed with value changing from system store to strict": {
			oldSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Default: "system-store",
				Value:   "",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Default: "system-store",
				Value:   "strict",
			},
			clusters: []*v3.Cluster{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "local",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster-1",
					},
					Status: v3.ClusterStatus{
						Conditions: []v3.ClusterCondition{
							{
								Type:   "AgentTlsStrictCheck",
								Status: "True",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster-2",
					},
					Status: v3.ClusterStatus{
						Conditions: []v3.ClusterCondition{
							{
								Type:   "AgentTlsStrictCheck",
								Status: "True",
							},
						},
					},
				},
			},
			operation: v1.Update,
			allowed:   true,
		},
		"update forbidden from system store to strict due to incorrect value on target status": {
			oldSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Default: "system-store",
				Value:   "system-store",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Default: "strict",
				Value:   "strict",
			},
			clusters: []*v3.Cluster{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "local",
					},
					Status: v3.ClusterStatus{
						Conditions: []v3.ClusterCondition{
							{
								Type:   "AgentTlsStrictCheck",
								Status: "True",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster-1",
					},
					Status: v3.ClusterStatus{
						Conditions: []v3.ClusterCondition{
							{
								Type:   "AgentTlsStrictCheck",
								Status: "True",
							},
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name: "cluster-2",
					},
					Status: v3.ClusterStatus{
						Conditions: []v3.ClusterCondition{
							{
								Type:   "AgentTlsStrictCheck",
								Status: "False",
							},
						},
					},
				},
			},
			operation: v1.Update,
			allowed:   false,
		},
		"update forbidden on error to list clusters": {
			oldSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Default: "system-store",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
				Default: "strict",
			},
			operation:          v1.Update,
			clusterListerFails: true,
			allowed:            false,
		},
		"ineffectual update allowed": {
			oldSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AgentTLSMode,
				},
			},
			operation: v1.Update,
			allowed:   true,
		},
	}
	for name, tc := range tests {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			clusterCache := fake.NewMockNonNamespacedCacheInterface[*v3.Cluster](ctrl)
			force := tc.newSetting.Annotations["cattle.io/force"]
			if tc.operation == v1.Update && force != "true" && len(tc.clusters) > 0 {
				clusterCache.EXPECT().List(gomock.Any()).Return(tc.clusters, nil)
			}
			if tc.clusterListerFails {
				clusterCache.EXPECT().List(gomock.Any()).Return(tc.clusters, errors.New("some error"))
			}
			v := setting.NewValidator(clusterCache, nil)
			admitters := v.Admitters()
			require.Len(t, admitters, 1)

			oldSetting, err := json.Marshal(tc.oldSetting)
			require.NoError(t, err)
			newSetting, err := json.Marshal(tc.newSetting)
			require.NoError(t, err)

			res, err := admitters[0].Admit(&admission.Request{
				AdmissionRequest: v1.AdmissionRequest{
					Object: runtime.RawExtension{
						Raw: newSetting,
					},
					OldObject: runtime.RawExtension{
						Raw: oldSetting,
					},
					Operation: tc.operation,
				},
			})
			require.NoError(t, err)
			assert.Equal(t, tc.allowed, res.Allowed)
		})
	}
}
