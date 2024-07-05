package setting_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/setting"
)

type SettingSuite struct {
	suite.Suite
}

func TestRetentionFieldsValidation(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(SettingSuite))
}

var (
	gvk = metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "Setting"}
	gvr = metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "settings"}
)

type retentionTest struct {
	setting string
	value   string
	allowed bool
}

func (t *retentionTest) name() string {
	return t.setting + "_" + t.value
}

func (t *retentionTest) toSetting() ([]byte, error) {
	return json.Marshal(v3.Setting{
		ObjectMeta: metav1.ObjectMeta{
			Name: t.setting,
		},
		Value: t.value,
	})
}
func (t *retentionTest) toOldSetting() ([]byte, error) {
	return json.Marshal(v3.Setting{
		ObjectMeta: metav1.ObjectMeta{
			Name: t.setting,
		},
	})
}

var retentionTests = []retentionTest{
	{
		setting: "disable-inactive-user-after",
		value:   "",
		allowed: true,
	},
	{
		setting: "delete-inactive-user-after",
		value:   "",
		allowed: true,
	},
	{
		setting: "user-last-login-default",
		value:   "",
		allowed: true,
	},
	{
		setting: "user-retention-cron",
		value:   "",
		allowed: true,
	},
	{
		setting: "disable-inactive-user-after",
		value:   "2h30m",
		allowed: true,
	},
	{
		setting: "delete-inactive-user-after",
		value:   setting.MinDeleteInactiveUserAfter.String(),
		allowed: true,
	},
	{
		setting: "user-last-login-default",
		value:   "2024-01-08T00:00:00Z",
		allowed: true,
	},
	{
		setting: "user-retention-cron",
		value:   "* * * * *",
		allowed: true,
	},
	{
		setting: "disable-inactive-user-after",
		value:   "1w",
	},
	{
		setting: "delete-inactive-user-after",
		value:   "2d",
	},
	{
		setting: "user-last-login-default",
		value:   "foo",
	},
	{
		setting: "user-retention-cron",
		value:   "* * * * * *",
	},
	{
		setting: "disable-inactive-user-after",
		value:   "-1h",
	},
	{
		setting: "delete-inactive-user-after",
		value:   "-1h",
	},
	{
		setting: "delete-inactive-user-after",
		value:   (setting.MinDeleteInactiveUserAfter - time.Second).String(),
	},
}

func (s *SettingSuite) TestValidateRetentionSettingsOnUpdate() {
	s.validate(v1.Update)
}

func (s *SettingSuite) TestValidateRetentionSettingsOnCreate() {
	s.validate(v1.Create)
}

func (s *SettingSuite) validate(op v1.Operation) {
	admitter := s.setup()

	for _, test := range retentionTests {
		test := test
		s.Run(test.name(), func() {
			t := s.T()
			t.Parallel()

			oldObjRaw, err := test.toOldSetting()
			assert.NoError(t, err, "failed to marshal old Setting")

			objRaw, err := test.toSetting()
			assert.NoError(t, err, "failed to marshal Setting")

			resp, err := admitter.Admit(newRequest(op, objRaw, oldObjRaw))
			if assert.NoError(t, err, "Admit failed") {
				assert.Equalf(t, test.allowed, resp.Allowed, "expected allowed %v got %v message=%v", test.allowed, resp.Allowed, resp.Result)
			}
		})
	}
}

func (s *SettingSuite) setup() admission.Admitter {
	validator := setting.NewValidator(nil)
	s.Len(validator.Admitters(), 1, "expected 1 admitter")

	return validator.Admitters()[0]
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
					Name: "agent-tls-mode",
				},
				Default: "system-store",
			},
			operation: v1.Create,
			allowed:   true,
		},
		"create allowed for strict": {
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "agent-tls-mode",
				},
				Default: "strict",
			},
			operation: v1.Create,
			allowed:   true,
		},
		"update forbidden due to missing status": {
			oldSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "agent-tls-mode",
				},
				Value: "system-store",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "agent-tls-mode",
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
					Name: "agent-tls-mode",
				},
				Default: "system-store",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "agent-tls-mode",
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
		"update allowed with cluster status and force annotation": {
			oldSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "agent-tls-mode",
				},
				Value: "system-store",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "agent-tls-mode",
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
					Name: "agent-tls-mode",
				},
				Default: "strict",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "agent-tls-mode",
				},
				Default: "system-store",
			},
			operation: v1.Update,
			allowed:   true,
		},
		"update allowed from system store to strict": {
			oldSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "agent-tls-mode",
				},
				Default: "system-store",
				Value:   "system-store",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "agent-tls-mode",
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
					Name: "agent-tls-mode",
				},
				Default: "system-store",
				Value:   "",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "agent-tls-mode",
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
					Name: "agent-tls-mode",
				},
				Default: "system-store",
				Value:   "system-store",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "agent-tls-mode",
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
					Name: "agent-tls-mode",
				},
				Default: "system-store",
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "agent-tls-mode",
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
					Name: "agent-tls-mode",
				},
			},
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "agent-tls-mode",
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
			_, force := tc.newSetting.Annotations["cattle.io/force"]
			if tc.operation == v1.Update && !force && len(tc.clusters) > 0 {
				clusterCache.EXPECT().List(gomock.Any()).Return(tc.clusters, nil)
			}
			if tc.clusterListerFails {
				clusterCache.EXPECT().List(gomock.Any()).Return(tc.clusters, errors.New("some error"))
			}
			v := setting.NewValidator(clusterCache)
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
