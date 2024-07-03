package setting

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/rancher/webhook/pkg/admission"
)

func TestValidateAgentTLSMode(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		oldSetting         v3.Setting
		newSetting         v3.Setting
		operation          admissionv1.Operation
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
			operation: admissionv1.Create,
			allowed:   true,
		},
		"create allowed for strict": {
			newSetting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "agent-tls-mode",
				},
				Default: "strict",
			},
			operation: admissionv1.Create,
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
			operation: admissionv1.Update,
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
			operation: admissionv1.Update,
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
			operation: admissionv1.Update,
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
			operation: admissionv1.Update,
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
								Status: "True",
							},
						},
					},
				},
			},
			operation: admissionv1.Update,
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
			operation: admissionv1.Update,
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
			operation:          admissionv1.Update,
			clusterListerFails: true,
			allowed:            false,
		},
	}
	for name, tc := range tests {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			clusterCache := fake.NewMockNonNamespacedCacheInterface[*v3.Cluster](ctrl)
			_, force := tc.newSetting.Annotations["cattle.io/force"]
			if tc.operation == admissionv1.Update && !force && len(tc.clusters) > 0 {
				clusterCache.EXPECT().List(gomock.Any()).Return(tc.clusters, nil)
			}
			if tc.clusterListerFails {
				clusterCache.EXPECT().List(gomock.Any()).Return(tc.clusters, errors.New("some error"))
			}
			v := NewValidator(clusterCache)
			admitters := v.Admitters()
			require.Len(t, admitters, 1)

			oldSetting, err := json.Marshal(tc.oldSetting)
			require.NoError(t, err)
			newSetting, err := json.Marshal(tc.newSetting)
			require.NoError(t, err)

			res, err := admitters[0].Admit(&admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
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

func TestEffectiveValue(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		setting v3.Setting
		want    string
	}{
		"empty": {
			setting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
			},
			want: "",
		},
		"only default": {
			setting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Default: "some-default",
			},
			want: "some-default",
		},
		"only value": {
			setting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Value: "some-value",
			},
			want: "some-value",
		},
		"same default and value": {
			setting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Default: "hello",
				Value:   "hello",
			},
			want: "hello",
		},
		"value overrides default": {
			setting: v3.Setting{
				ObjectMeta: metav1.ObjectMeta{
					Name: "foo",
				},
				Default: "hello",
				Value:   "some-value",
			},
			want: "some-value",
		},
	}
	for name, tc := range tests {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := effectiveValue(tc.setting); got != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}
