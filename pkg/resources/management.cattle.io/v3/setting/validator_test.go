package setting_test

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"testing"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/setting"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"go.uber.org/mock/gomock"
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

func (s *SettingSuite) TestValidateDisableInactiveUserAfterOnUpdate() {
	s.validateDisableInactiveUserAfter(v1.Update)
}

func (s *SettingSuite) TestValidateDisableInactiveUserAfterOnCreate() {
	s.validateDisableInactiveUserAfter(v1.Create)
}

func (s *SettingSuite) validateDisableInactiveUserAfter(op v1.Operation) {
	tests := []struct {
		desc              string
		value             string
		userSessionTTL    string
		userSessionTTLErr error
		allowed           bool
	}{
		{
			desc:    "disabled",
			value:   "",
			allowed: true,
		},
		{
			desc:    "zero value", // Semantically is the same as an empty value.
			value:   "0s",
			allowed: true,
		},
		{
			desc:           "reasonable value larger than user session ttl",
			userSessionTTL: "960",
			value:          "16h1s",
			allowed:        true,
		},
		{
			desc:           "nonsensical user session ttl value",
			userSessionTTL: "foo",
			value:          "15h",
			allowed:        true,
		},
		{
			desc:              "error getting user session ttl value",
			userSessionTTLErr: errors.New("some error"),
			value:             "16h", // 960 minutes.
			allowed:           true,
		},
		{
			desc:           "value with minutes and seconds",
			userSessionTTL: "960",
			value:          "15h59m59s",
		},
		{
			desc:  "days modifier",
			value: "1d",
		},
		{
			desc:  "weeks modifier",
			value: "1w",
		},
		{
			desc:  "negative value",
			value: "-1h",
		},
	}

	for _, test := range tests {
		test := test
		s.T().Run(test.desc, func(t *testing.T) {
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

			validator := setting.NewValidator(nil, settingCache)
			s.testAdmit(t, validator, &v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.DisableInactiveUserAfter,
				},
			}, &v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.DisableInactiveUserAfter,
				},
				Value: test.value,
			}, op, test.allowed)
		})
	}
}

func (s *SettingSuite) TestValidateDeleteInactiveUserAfterOnUpdate() {
	s.validateDeleteInactiveUserAfter(v1.Update)
}

func (s *SettingSuite) TestValidateDeleteInactiveUserAfterOnCreate() {
	s.validateDeleteInactiveUserAfter(v1.Create)
}

func (s *SettingSuite) validateDeleteInactiveUserAfter(op v1.Operation) {
	tests := []struct {
		desc              string
		value             string
		userSessionTTL    string
		userSessionTTLErr error
		allowed           bool
	}{
		{
			desc:    "disabled",
			value:   "",
			allowed: true,
		},
		{
			desc:    "zero value", // Semantically is the same as an empty value.
			value:   "0s",
			allowed: true,
		},
		{
			desc:           "min allowed value",
			userSessionTTL: "960",
			value:          setting.MinDeleteInactiveUserAfter.String(),
			allowed:        true,
		},
		{
			desc:           "nonsensical user session ttl value",
			userSessionTTL: "foo",
			value:          setting.MinDeleteInactiveUserAfter.String(),
			allowed:        true,
		},
		{
			desc:              "error getting user session ttl value",
			userSessionTTLErr: errors.New("some error"),
			value:             setting.MinDeleteInactiveUserAfter.String(),
			allowed:           true,
		},
		{
			desc:           "value less than user session ttl",
			userSessionTTL: strconv.Itoa(int((setting.MinDeleteInactiveUserAfter + time.Hour).Minutes())),
			value:          setting.MinDeleteInactiveUserAfter.String(),
		},
		{
			desc:  "value less than min allowed",
			value: (setting.MinDeleteInactiveUserAfter - time.Second).String(),
		},
		{
			desc:  "days modifier",
			value: "1d",
		},
		{
			desc:  "weeks modifier",
			value: "1w",
		},
		{
			desc:  "negative value",
			value: "-1h",
		},
	}

	for _, test := range tests {
		test := test
		s.T().Run(test.desc, func(t *testing.T) {
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

			validator := setting.NewValidator(nil, settingCache)
			s.testAdmit(t, validator, &v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.DeleteInactiveUserAfter,
				},
			}, &v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.DeleteInactiveUserAfter,
				},
				Value: test.value,
			}, op, test.allowed)
		})
	}
}

func (s *SettingSuite) TestValidateUserRetentionCronOnUpdate() {
	s.validateUserRetentionCron(v1.Update)
}

func (s *SettingSuite) TestValidateUserRetentionCronOnCreate() {
	s.validateUserRetentionCron(v1.Create)
}

func (s *SettingSuite) validateUserRetentionCron(op v1.Operation) {
	tests := []struct {
		desc    string
		value   string
		allowed bool
	}{
		{
			desc:    "disabled",
			value:   "",
			allowed: true,
		},
		{
			desc:    "valid cron expression",
			value:   "* * * * *",
			allowed: true,
		},
		{
			desc:  "non-standard cron expression",
			value: "* * * * * *",
		},
		{
			desc:  "nonsensical value",
			value: "foo",
		},
	}

	for _, test := range tests {
		test := test
		s.T().Run(test.desc, func(t *testing.T) {
			t.Parallel()

			validator := setting.NewValidator(nil, nil)
			s.testAdmit(t, validator, &v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.UserRetentionCron,
				},
			}, &v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.UserRetentionCron,
				},
				Value: test.value,
			}, op, test.allowed)
		})
	}
}

func (s *SettingSuite) TestValidateUserLastLoginDefaultOnUpdate() {
	s.validateUserLastLoginDefault(v1.Update)
}

func (s *SettingSuite) TestValidateUserLastLoginDefaultOnCreate() {
	s.validateUserLastLoginDefault(v1.Create)
}

func (s *SettingSuite) validateUserLastLoginDefault(op v1.Operation) {
	tests := []struct {
		desc    string
		value   string
		allowed bool
	}{
		{
			desc:    "disabled",
			value:   "",
			allowed: true,
		},
		{
			desc:    "valid RFC3339 date time",
			value:   "2024-01-08T00:00:00Z", // RFC3339.
			allowed: true,
		},
		{
			desc:  "invalid RFC3339 date time",
			value: "20240108T000000Z", // ISO8601.
		},
		{
			desc:  "nonsensical value",
			value: "foo",
		},
	}

	for _, test := range tests {
		test := test
		s.T().Run(test.desc, func(t *testing.T) {
			t.Parallel()

			validator := setting.NewValidator(nil, nil)
			s.testAdmit(t, validator, &v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.UserLastLoginDefault,
				},
			}, &v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.UserLastLoginDefault,
				},
				Value: test.value,
			}, op, test.allowed)
		})
	}
}

func (s *SettingSuite) TestValidateClusterAgentSchedulingPriorityClass() {
	tests := []struct {
		name     string
		newValue string
		allowed  bool
	}{
		{
			name:    "valid update to PC - value",
			allowed: true,
			newValue: `
{
	"value": 1356,
	"preemptionPolicy": "PreemptLowerPriority"
}
`,
		},
		{
			name:    "valid update to PC - preemption",
			allowed: true,
			newValue: `
{
	"value": 10000000,
	"preemptionPolicy": "Never"
}
`,
		},
		{
			name:    "valid update to PC - both",
			allowed: true,
			newValue: `
{
	"value": 1000,
	"preemptionPolicy": "Never"
}
`,
		},
		{
			name:    "invalid update to PC - value lower than 1 billion",
			allowed: false,
			newValue: `
{
	"value": -1000000001,
	"preemptionPolicy": "PreemptLowerPriority"
}
`,
		},
		{
			name:    "invalid update to PC - value greater than 1 billion",
			allowed: false,
			newValue: `
{
	"value": 1000000001,
	"preemptionPolicy": "PreemptLowerPriority"
}
`,
		},
		{
			name:    "invalid update to PC - invalid preemption string",
			allowed: false,
			newValue: `
{
	"value": 100000000,
	"preemptionPolicy": "invalid"
}
`,
		},
		{
			name:    "invalid update to PC - invalid object",
			allowed: false,
			newValue: `
{
	"invalid": 100000000,
}
`,
		},
		{
			name:     "base case - no customization",
			allowed:  true,
			newValue: "",
		},
	}

	for _, test := range tests {
		test := test
		s.T().Run(test.name, func(t *testing.T) {
			t.Parallel()

			validator := setting.NewValidator(nil, nil)
			s.testAdmit(t, validator, nil, &v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.CattleClusterAgentPriorityClass,
				},
				Value: test.newValue,
			}, v1.Update, test.allowed)
		})
	}
}

func (s *SettingSuite) TestValidateClusterAgentSchedulingPodDisruptionBudget() {
	tests := []struct {
		name     string
		newValue string
		allowed  bool
	}{
		{
			name:    "valid update to PDB - integer",
			allowed: true,
			newValue: `
{
	"minAvailable": "0",
	"maxUnavailable": "1"
}`,
		},
		{
			name:    "valid update to PDB - percent",
			allowed: true,
			newValue: `
{
	"minAvailable": "0",
	"maxUnavailable": "50%"
}`,
		},
		{
			name:    "valid update to PDB - both set to zero",
			allowed: true,
			newValue: `
{
	"minAvailable": "0",
	"maxUnavailable": "0"
}`,
		},
		{
			name:    "invalid update to PDB - both fields set",
			allowed: false,
			newValue: `
{
	"minAvailable": "1",
	"maxUnavailable": "1"
}`,
		},
		{
			name:    "invalid update to PDB - field set to negative value",
			allowed: false,
			newValue: `
{
	"minAvailable": "-1",
	"maxUnavailable": "0"
}`,
		},
		{
			name:    "invalid update to PDB - field set to negative value",
			allowed: false,
			newValue: `
{
	"minAvailable": "0",
	"maxUnavailable": "-1"
}`,
		},
		{
			name:    "invalid update to PDB - field set to invalid percentage value",
			allowed: false,
			newValue: `
{
	"minAvailable": "50.5%",
	"maxUnavailable": "0"
}`,
		},
		{
			name:    "invalid update to PDB - field set to non-number string",
			allowed: false,
			newValue: `
{
	"minAvailable": "five",
	"maxUnavailable": "0"
}`,
		},
		{
			name:    "invalid update to PDB - field set to non-number string",
			allowed: false,
			newValue: `
{
	"minAvailable": "0",
	"maxUnavailable": "five"
}`,
		},
		{
			name:    "invalid update to PDB - bad object",
			allowed: false,
			newValue: `
{
	"fake": "0",
}`,
		},
		{
			name:     "base case - no customization",
			allowed:  true,
			newValue: "",
		},
	}

	for _, test := range tests {
		test := test
		s.T().Run(test.name, func(t *testing.T) {
			t.Parallel()

			validator := setting.NewValidator(nil, nil)
			s.testAdmit(t, validator, nil, &v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.CattleClusterAgentPodDisruptionBudget,
				},
				Value: test.newValue,
			}, v1.Update, test.allowed)
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
			desc:    "zero value",
			value:   "0",
			allowed: true,
		},
		{
			desc:    "reasonable value",
			value:   "960", // 16h
			allowed: true,
		},
		{
			desc:         "less than disable-inactive-user-after",
			value:        "960",
			disableAfter: "168h",
			allowed:      true,
		},
		{
			desc:        "less than delete-inactive-user-after",
			value:       "960",
			deleteAfter: "336h",
			allowed:     true,
		},
		{
			desc:         "less than both",
			value:        "960",
			disableAfter: "168h",
			deleteAfter:  "336h",
			allowed:      true,
		},
		{
			desc:         "less than both zero values",
			value:        "960",
			disableAfter: "0s",
			deleteAfter:  "0s",
			allowed:      true,
		},
		{
			desc:         "can't parse disable-inactive-user-after",
			value:        "960",
			disableAfter: "foo",
			allowed:      true,
		},
		{
			desc:        "can't parse delete-inactive-user-after",
			value:       "960",
			deleteAfter: "foo",
			allowed:     true,
		},
		{
			desc:            "error getting disable-inactive-user-after",
			value:           "960",
			disableAfterErr: errors.New("some error"),
			allowed:         true,
		},
		{
			desc:           "error getting delete-inactive-user-after",
			value:          "960",
			deleteAfterErr: errors.New("some error"),
			allowed:        true,
		},
		{
			desc:         "negative disable-inactive-user-after",
			value:        "960",
			disableAfter: "-1h",
			allowed:      true,
		},
		{
			desc:        "negative delete-inactive-user-after",
			value:       "960",
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
		s.T().Run(test.desc, func(t *testing.T) {
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

				// Make sure we use the effective value of the setting
				// by alternating between setting.Value and setting.Default.
				if settingGetCalledTimes%2 == 0 {
					setting.Value = value
				} else {
					setting.Default = value
				}

				return setting, nil
			}).AnyTimes()

			validator := setting.NewValidator(nil, settingCache)
			s.testAdmit(t, validator, &v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AuthUserSessionTTLMinutes,
				},
			}, &v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AuthUserSessionTTLMinutes,
				},
				Value: test.value,
			}, op, test.allowed)
		})
	}
}

func (s *SettingSuite) testAdmit(t *testing.T, validator *setting.Validator, oldSetting, newSetting *v3.Setting, op v1.Operation, allowed bool) {
	oldObjRaw, err := json.Marshal(oldSetting)
	require.NoError(t, err, "failed to marshal old Setting")

	objRaw, err := json.Marshal(newSetting)
	require.NoError(t, err, "failed to marshal Setting")

	resp, err := validator.Admitters()[0].Admit(newRequest(op, objRaw, oldObjRaw))
	require.NoError(t, err)
	assert.Equal(t, allowed, resp.Allowed)
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

func (s *SettingSuite) TestValidateAuthUserSessionTTLIdleMinutesOnUpdate() {
	s.validateAuthUserSessionTTLIdleMinutes(v1.Update, s.T())
}

func (s *SettingSuite) TestValidateAuthUserSessionTTLIdleMinutesOnCreate() {
	s.validateAuthUserSessionTTLIdleMinutes(v1.Create, s.T())
}

func (s *SettingSuite) validateAuthUserSessionTTLIdleMinutes(op v1.Operation, t *testing.T) {
	ctrl := gomock.NewController(t)
	settingCache := fake.NewMockNonNamespacedCacheInterface[*v3.Setting](ctrl)

	tests := []struct {
		name      string
		value     string
		mockSetup func()
		allowed   bool
	}{
		{
			name:  "valid value",
			value: "10",
			mockSetup: func() {
				settingCache.EXPECT().Get(gomock.Any()).DoAndReturn(func(_ string) (*v3.Setting, error) {
					return &v3.Setting{
						Value:   "",
						Default: "960",
					}, nil
				}).Times(1)
			},
			allowed: true,
		},
		{
			name:  "value is too high",
			value: "10000",
			mockSetup: func() {
				settingCache.EXPECT().Get(gomock.Any()).DoAndReturn(func(_ string) (*v3.Setting, error) {
					return &v3.Setting{
						Value:   "",
						Default: "960",
					}, nil
				}).Times(1)
			},
			allowed: false,
		},
		{
			name:      "value is too low",
			value:     "-10",
			mockSetup: func() {},
			allowed:   false,
		},
		{
			name:      "value cannot be 0",
			value:     "0",
			mockSetup: func() {},
			allowed:   false,
		},
		{
			name:      "value cannot be 0.5",
			value:     "0.5",
			mockSetup: func() {},
			allowed:   false,
		},
		{
			name:      "value cannot be a char",
			value:     "A",
			mockSetup: func() {},
			allowed:   false,
		},
		{
			name:  "invalid value due to auth-session-user-ttl-minutes",
			value: "12",
			mockSetup: func() {
				settingCache.EXPECT().Get(gomock.Any()).DoAndReturn(func(_ string) (*v3.Setting, error) {
					return &v3.Setting{
						Value:   "10",
						Default: "",
					}, nil
				}).Times(1)
			},
			allowed: false,
		},
		{
			name:  "valid because auth-user-session-ttl-minutes equal 0 means token lives forever",
			value: "1",
			mockSetup: func() {
				settingCache.EXPECT().Get(gomock.Any()).DoAndReturn(func(_ string) (*v3.Setting, error) {
					return &v3.Setting{
						Value:   "0",
						Default: "",
					}, nil
				}).Times(1)
			},
			allowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tt.mockSetup()

			validator := setting.NewValidator(nil, settingCache)
			s.testAdmit(t, validator, &v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AuthUserSessionIdleTTLMinutes,
				},
			}, &v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: setting.AuthUserSessionIdleTTLMinutes,
				},
				Value: tt.value,
			}, op, tt.allowed)
		})
	}
}
