package cluster

import (
	"fmt"
	"strings"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/common"
	"github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	k8sv1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"
)

func Test_isValidName(t *testing.T) {
	tests := []struct {
		name, clusterName, clusterNamespace string
		clusterExists                       bool
		want                                bool
	}{
		{
			name:             "local cluster in fleet-local",
			clusterName:      "local",
			clusterNamespace: "fleet-local",
			clusterExists:    true,
			want:             true,
		},
		{
			name:             "local cluster in fleet-local, cluster does not exist",
			clusterName:      "local",
			clusterNamespace: "fleet-local",
			clusterExists:    false,
			want:             true,
		},
		{
			name:             "local cluster not in fleet-local",
			clusterName:      "local",
			clusterNamespace: "fleet-default",
			clusterExists:    true,
			want:             false,
		},
		{
			name:             "c-xxxxx cluster exists",
			clusterName:      "c-12345",
			clusterNamespace: "default",
			clusterExists:    true,
			want:             true,
		},
		{
			name:             "c-xxxxx cluster does not exist",
			clusterName:      "c-xxxxx",
			clusterNamespace: "fleet-default",
			clusterExists:    false,
			want:             false,
		},
		{
			name:             "suffix matches c-xxxxx and cluster exists",
			clusterName:      "logic-xxxxx",
			clusterNamespace: "fleet-local",
			clusterExists:    true,
			want:             true,
		},
		{
			name:             "prefix matches c-xxxxx and cluster exists",
			clusterName:      "c-aaaaab",
			clusterNamespace: "fleet-default",
			clusterExists:    true,
			want:             true,
		},
		{
			name:             "substring matches c-xxxxx and cluster exists",
			clusterName:      "logic-1a3c5bool",
			clusterNamespace: "cattle-system",
			clusterExists:    true,
			want:             true,
		},
		{
			name:             "substring matches c-xxxxx and cluster does not exist",
			clusterName:      "logic-1a3c5bool",
			clusterNamespace: "cattle-system",
			clusterExists:    false,
			want:             true,
		},
		{
			name:             "name length is exactly 63 characters",
			clusterName:      "cq8oh6uvntypoitcfwrxfjjruz4kv2q6itimqkcgex1zqgm7oa3jbld9n0diika",
			clusterNamespace: "fleet-default",
			clusterExists:    false,
			want:             true,
		},
		{
			name:             "name length is 64 characters",
			clusterName:      "xd0pegoo51iswfkx173upiknot0dsgp0jkuausssk2vwunjrwalb2raypjntvtpa",
			clusterNamespace: "fleet-default",
			clusterExists:    false,
			want:             false,
		},
		{
			name:             "name length is 253 characters",
			clusterName:      "dxht2wgxbask8lpj4nfqmycykcsmzv6bwtl7xeo3nuxnw6tk07vofjjjmepy6avdhd03or2hnw8uqjtdh2lvbprh4v0rjochgealmptz4sqt3pt5stcce4eirk37ytjfquhodxknqqzpidll6txreiq9ppaaswuwpq8opadhqitfln2txsgowc80wwgkgikczh6f8fuihvvizf65tn2wbeysudyeofgltadug1cjwohm7n9yovrd0fiyxm0bk",
			clusterNamespace: "fleet-default",
			clusterExists:    false,
			want:             false,
		},
		{
			name:             "name containing . does not conform to RFC-1123",
			clusterName:      "cluster.test.name",
			clusterNamespace: "fleet-default",
			clusterExists:    false,
			want:             false,
		},
		{
			name:             "name containing uppercase characters does not conform to RFC-1123",
			clusterName:      "CLUSTER-NAME",
			clusterNamespace: "fleet-default",
			clusterExists:    true,
			want:             false,
		},
		{
			name:             "name cannot begin with hyphen",
			clusterName:      "-CLUSTER-NAME",
			clusterNamespace: "fleet-default",
			clusterExists:    true,
			want:             false,
		},
		{
			name:             "name cannot only be hyphens",
			clusterName:      "---------------------------",
			clusterNamespace: "fleet-default",
			clusterExists:    false,
			want:             false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidName(tt.clusterName, tt.clusterNamespace, tt.clusterExists); got != tt.want {
				t.Errorf("isValidName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidNoProxy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		oldCluster *v1.Cluster
		newCluster *v1.Cluster
		request    *admission.Request
		expected   bool
	}{
		{
			name: "valid cluster create operation",
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
				},
			},
			newCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "NO_PROXY",
							Value: "valid,value",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "valid cluster create operation lowercase",
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
				},
			},
			newCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "no_proxy",
							Value: "valid,value",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "invalid cluster create operation",
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
				},
			},
			newCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "NO_PROXY",
							Value: "something bad",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "invalid cluster create operation lowercase",
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Create,
				},
			},
			newCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "no_proxy",
							Value: "something bad",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "valid cluster update operation",
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{},
				},
			},
			newCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "NO_PROXY",
							Value: "valid,value",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "valid cluster update operation lowercase",
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{},
				},
			},
			newCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "no_proxy",
							Value: "valid,value",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "valid cluster update operation",
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "NO_PROXY",
							Value: "previous,value",
						},
					},
				},
			},
			newCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "NO_PROXY",
							Value: "valid,value",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "valid malformed cluster update operation",
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "NO_PROXY",
							Value: "previous, bad , value",
						},
					},
				},
			},
			newCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "NO_PROXY",
							Value: "new, bad, value",
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "invalid cluster update operation",
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{},
				},
			},
			newCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "NO_PROXY",
							Value: "new, bad, value",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "invalid cluster update operation lowercase",
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{},
				},
			},
			newCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "no_proxy",
							Value: "new, bad, value",
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "invalid cluster update operation",
			request: &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: admissionv1.Update,
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "NO_PROXY",
							Value: "a,previous,value",
						},
					},
				},
			},
			newCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "NO_PROXY",
							Value: "new, bad, value",
						},
					},
				},
			},
			expected: false,
		},
	}

	for _, tst := range tests {
		tst := tst
		t.Run(tst.name, func(t *testing.T) {
			resp := validateHTTPNoProxyVariable(tst.request, tst.oldCluster, tst.newCluster)

			var oldValue, newValue string
			if tst.newCluster != nil && len(tst.newCluster.Spec.AgentEnvVars) > 0 {
				newValue = tst.newCluster.Spec.AgentEnvVars[0].Value
			}
			if tst.oldCluster != nil && len(tst.oldCluster.Spec.AgentEnvVars) > 0 {
				oldValue = tst.oldCluster.Spec.AgentEnvVars[0].Value
			}

			if (resp.Result == nil || resp.Result.Status != failureStatus) && !tst.expected {
				if oldValue == "" && newValue != "" {
					t.Logf("Expected error when providing NO_PROXY value of '%s'", newValue)
				}
				if oldValue != "" && newValue != "" {
					t.Logf("Expected error when updating from old value of '%s' to new value of '%s'", oldValue, newValue)
				}
				t.Fail()
			}

			if (resp.Result != nil && resp.Result.Status == failureStatus) && tst.expected {
				if oldValue == "" && newValue != "" {
					t.Logf("Encountered unexpected error when providing NO_PROXY value of '%s'", newValue)
				}
				if oldValue != "" && newValue != "" {
					t.Logf("Encountered unexpected error when updating from old value of '%s' to new value of '%s'", oldValue, newValue)
				}
				t.Fail()
			}
		})
	}
}

func TestValidateMachinePoolName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, value string
		fail        bool
	}{
		{
			name:  "muchTooLong",
			value: strings.Repeat("12345678", 8),
			fail:  true,
		},
		{
			name:  "barelyUnderLimit",
			value: strings.Repeat("12345678", 7),
			fail:  false,
		},
		{
			name:  "regularLookingString",
			value: "regular-string-test",
			fail:  false,
		},
	}

	a := provisioningAdmitter{}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			resp := admissionv1.AdmissionResponse{}

			err := a.validateMachinePoolNames(
				&admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Create}},
				&resp,
				&v1.Cluster{
					Spec: v1.ClusterSpec{
						RKEConfig: &v1.RKEConfig{
							MachinePools: []v1.RKEMachinePool{{Name: tt.value}},
						},
					},
				},
			)

			if err != nil {
				t.Errorf("got error when none was expected: %v", err)
			}

			if tt.fail {
				if resp.Result == nil {
					t.Error("got no result on response when one was expected")
				}
				if resp.Result.Status != "Failure" {
					t.Errorf("got %v when Failure was expected", resp.Result.Status)
				}
			} else {
				if resp.Result != nil {
					t.Error("got result on response when none was expected")
				}
			}
		})
	}
}

func TestValidateSystemAgentDataDirectory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		cluster       *v1.Cluster
		oldCluster    *v1.Cluster
		shouldSucceed bool
	}{
		{
			name: "base",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
				},
			},
			shouldSucceed: true,
		},
		{
			name: "same env var",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "a",
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "a",
						},
					},
				},
			},
			shouldSucceed: true,
		},
		{
			name: "change env var",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "a",
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "b",
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name: "same data directory",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "a",
							},
						},
					},
				},
			},
			shouldSucceed: true,
		},
		{
			name: "change data directory",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "b",
							},
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name: "add unrelated env var",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_TEST_VAR",
							Value: "a",
						},
					},
				},
			},
			shouldSucceed: true,
		},
		{
			name: "migrate env var",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "a",
						},
					},
				},
			},
			shouldSucceed: true,
		},
		{
			name: "change during migration",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "b",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "a",
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name: "reverse migrate env var",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "a",
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "a",
							},
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name: "removing env var",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig:    &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "a",
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name: "removing data directory",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig:    &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "a",
							},
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name: "adding env var",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "a",
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig:    &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{},
				},
			},
			shouldSucceed: false,
		},
		{
			name: "adding data directory",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig:    &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{},
				},
			},
			shouldSucceed: false,
		},
		{
			name: "add env var with data directory",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "a",
							},
						},
					},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "b",
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "a",
							},
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name: "set data directory without migrating",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "a",
							},
						},
					},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "a",
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "a",
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name: "update unrelated vars",
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_TEST_VAR",
							Value: "a",
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_TEST_VAR",
							Value: "b",
						},
					},
				},
			},
			shouldSucceed: true,
		},
	}

	a := provisioningAdmitter{}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			response := a.validateSystemAgentDataDirectory(tt.oldCluster, tt.cluster)
			assert.Equal(t, tt.shouldSucceed, response.Allowed)
		})
	}
}

func TestValidateDataDirectories(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		request       *admission.Request
		cluster       *v1.Cluster
		oldCluster    *v1.Cluster
		shouldSucceed bool
	}{
		{
			name:          "no rkeconfig",
			request:       &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster:       &v1.Cluster{},
			oldCluster:    nil,
			shouldSucceed: true,
		},
		{
			name:    "Create",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Create}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
				},
			},
			oldCluster:    nil,
			shouldSucceed: true,
		},
		{
			name:    "Create with CATTLE_AGENT_VAR_DIR",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Create}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "/a",
						},
					},
				},
			},
			oldCluster:    nil,
			shouldSucceed: false,
		},
		{
			name:    "CREATE distro data dir is relative",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Create}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								K8sDistro: "a",
							},
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name:    "CREATE provisioning data dir is relative",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Create}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								Provisioning: "a",
							},
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name:    "CREATE system agent data dir is relative",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Create}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "a",
							},
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name:    "CREATE distro data dir == provisioning data dir",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Create}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								K8sDistro:    "/a",
								Provisioning: "/a",
							},
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name:    "CREATE distro data dir == system agent data dir",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Create}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								K8sDistro:   "/a",
								SystemAgent: "/a",
							},
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name:    "CREATE provisioning data dir == system agent data dir",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Create}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								Provisioning: "/a",
								SystemAgent:  "/a",
							},
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name:    "CREATE distro data dir contains provisioning data dir",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Create}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								K8sDistro:    "/a",
								Provisioning: "/a/b",
							},
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name:    "CREATE provisioning data dir contains distro data dir",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Create}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								K8sDistro:    "/a/b",
								Provisioning: "/a",
							},
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name:    "Delete",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Delete}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "/a",
						},
					},
				},
			},
			oldCluster:    nil,
			shouldSucceed: true,
		},
		{
			name:          "Update unmanaged cluster",
			request:       &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster:       &v1.Cluster{},
			oldCluster:    &v1.Cluster{},
			shouldSucceed: true,
		},
		{
			name:    "CATTLE_AGENT_VAR_DIR not present in old or new",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig:    &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig:    &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{},
				},
			},
			shouldSucceed: true,
		},
		{
			name:    "CATTLE_AGENT_VAR_DIR present in old and new",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "/a",
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "/a",
						},
					},
				},
			},
			shouldSucceed: true,
		},
		{
			name:    "CATTLE_AGENT_VAR_DIR present in old and new but different value",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "/a",
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "/b",
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name:    "CATTLE_AGENT_VAR_DIR present in old and migrated to new",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "/a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{},
					AgentEnvVars: []rkev1.EnvVar{
						{
							Name:  "CATTLE_AGENT_VAR_DIR",
							Value: "/a",
						},
					},
				},
			},
			shouldSucceed: true,
		},
		{
			name:    "system-agent data dir changed",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "/a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								SystemAgent: "/b",
							},
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name:    "provisioning data dir changed",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								Provisioning: "/a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								Provisioning: "/b",
							},
						},
					},
				},
			},
			shouldSucceed: false,
		},
		{
			name:    "distro data dir changed",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								K8sDistro: "/a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							DataDirectories: rkev1.DataDirectories{
								K8sDistro: "/b",
							},
						},
					},
				},
			},
			shouldSucceed: false,
		},
	}

	a := provisioningAdmitter{}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			response := a.validateDataDirectories(tt.request, tt.oldCluster, tt.cluster)
			assert.Equal(t, tt.shouldSucceed, response.Allowed)
		})
	}
}

func TestValidateDataDirectoryFormat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		dir      string
		expected bool
	}{
		{
			name:     "relative",
			dir:      "home",
			expected: false,
		},
		{
			name:     "trailing slash",
			dir:      "/home/",
			expected: false,
		},
		{
			name:     "env var",
			dir:      "/$HOME",
			expected: false,
		},
		{
			name:     "env var",
			dir:      "/${HOME}",
			expected: false,
		},
		{
			name:     "expr",
			dir:      "/`pwd`",
			expected: false,
		},
		{
			name:     "expr",
			dir:      "/$(pwd)",
			expected: false,
		},
		{
			name:     "current directory",
			dir:      "/./tmp",
			expected: false,
		},
		{
			name:     "current directory",
			dir:      "/tmp/.",
			expected: false,
		},
		{
			name:     "parent directory",
			dir:      "/tmp/../tmp",
			expected: false,
		},
		{
			name:     "current directory",
			dir:      "/tmp/..",
			expected: false,
		},
		{
			name:     "valid",
			dir:      "/tmp",
			expected: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			response := validateDataDirectoryFormat(tt.dir, "Test")
			assert.Equal(t, tt.expected, response.Allowed)
		})
	}
}

func TestValidateDataDirectoryHierarchy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		dataDirs map[string]string
		expected bool
	}{
		{
			name: "equal paths",
			dataDirs: map[string]string{
				"a": "/a",
				"b": "/a",
			},
			expected: false,
		},
		{
			name: "nested paths",
			dataDirs: map[string]string{
				"a": "/a",
				"b": "/a/b",
			},
			expected: false,
		},
		{
			name: "nested paths",
			dataDirs: map[string]string{
				"a": "/a/b",
				"b": "/a",
			},
			expected: false,
		},
		{
			name: "distinct paths",
			dataDirs: map[string]string{
				"a": "/a",
				"b": "/b",
			},
			expected: true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			response := validateDataDirectoryHierarchy(tt.dataDirs)
			assert.Equal(t, tt.expected, response.Allowed)
		})
	}
}

func validateFailedPaths(s []string) func(t *testing.T, err field.ErrorList) {
	return func(t *testing.T, err field.ErrorList) {
		t.Helper()
		errPaths := make([]string, len(err))
		for i := 0; i < len(err); i++ {
			errPaths[i] = err[i].Field
		}

		if !assert.ElementsMatch(t, s, errPaths) {
			b := strings.Builder{}
			b.WriteString("Failed Fields and reasons: ")
			for _, v := range err {
				b.WriteString("\n* ")
				b.WriteString(v.Error())
			}
			fmt.Println(b.String())
		}
	}
}

func Test_validateAgentDeploymentCustomization(t *testing.T) {
	type args struct {
		customization *v1.AgentDeploymentCustomization
		path          *field.Path
	}

	tests := []struct {
		name         string
		args         args
		validateFunc func(t *testing.T, err field.ErrorList)
	}{
		{
			name: "empty",
			args: args{
				customization: nil,
				path:          field.NewPath("test"),
			},
			validateFunc: validateFailedPaths([]string{}),
		},
		{
			name: "Ok",
			args: args{
				customization: &v1.AgentDeploymentCustomization{
					AppendTolerations: []k8sv1.Toleration{
						{
							Key: "validkey",
						},
						{
							Key: "validkey.dot/dash",
						},
					},
					OverrideAffinity: &k8sv1.Affinity{
						NodeAffinity: &k8sv1.NodeAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: &k8sv1.NodeSelector{
								NodeSelectorTerms: []k8sv1.NodeSelectorTerm{
									{
										MatchExpressions: []k8sv1.NodeSelectorRequirement{
											{
												Key:      "validkey.dot",
												Operator: "equal",
											},
											{
												Key:      "validkey.dot/dash",
												Operator: "In",
											},
										},
										MatchFields: []k8sv1.NodeSelectorRequirement{
											{
												Key: "validkey.dot",
											},
											{
												Key: "validkey.dot/dash",
											},
										},
									},
								},
							},
							PreferredDuringSchedulingIgnoredDuringExecution: []k8sv1.PreferredSchedulingTerm{
								{
									Weight: 1,
									Preference: k8sv1.NodeSelectorTerm{
										MatchExpressions: []k8sv1.NodeSelectorRequirement{
											{
												Key:      "validkey.dot",
												Operator: "in",
											},
											{
												Key:      "validkey.dot/dash",
												Operator: "in",
											},
										},
										MatchFields: []k8sv1.NodeSelectorRequirement{
											{
												Key:      "validkey.dot",
												Operator: "in",
											},
											{
												Key:      "validkey.dot/dash",
												Operator: "in",
											},
										},
									},
								},
							},
						},
						PodAffinity: &k8sv1.PodAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: []k8sv1.PodAffinityTerm{
								{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"key": "validValue",
										},
										MatchExpressions: []metav1.LabelSelectorRequirement{
											{
												Key:      "validKey",
												Operator: "In",
												Values:   []string{""},
											},
										},
									},
								},
							},
							PreferredDuringSchedulingIgnoredDuringExecution: []k8sv1.WeightedPodAffinityTerm{
								{
									Weight: 1,
									PodAffinityTerm: k8sv1.PodAffinityTerm{
										NamespaceSelector: &metav1.LabelSelector{
											MatchLabels: nil,
											MatchExpressions: []metav1.LabelSelectorRequirement{
												{
													Key:      "validKey",
													Operator: "In",
													Values:   []string{""},
												},
												{
													Key:      "validKey2",
													Operator: "In",
													Values:   []string{""},
												},
											},
										},
									},
								},
							},
						},
						PodAntiAffinity: &k8sv1.PodAntiAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: []k8sv1.PodAffinityTerm{
								{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"key": "validValue",
										},
										MatchExpressions: []metav1.LabelSelectorRequirement{
											{
												Key:      "validKey",
												Operator: "In",
												Values:   []string{""},
											},
										},
									},
								},
							},
							PreferredDuringSchedulingIgnoredDuringExecution: []k8sv1.WeightedPodAffinityTerm{
								{
									Weight: 1,
									PodAffinityTerm: k8sv1.PodAffinityTerm{
										NamespaceSelector: &metav1.LabelSelector{
											MatchLabels: nil,
											MatchExpressions: []metav1.LabelSelectorRequirement{
												{
													Key:      "validKey",
													Operator: "In",
													Values:   []string{""},
												},
												{
													Key:      "validKey2",
													Operator: "In",
													Values:   []string{""},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				path: field.NewPath("test"),
			},
			validateFunc: validateFailedPaths([]string{}),
		},
		{
			name: "invalid-args",
			args: args{
				customization: &v1.AgentDeploymentCustomization{
					AppendTolerations: []k8sv1.Toleration{
						{
							Key: "`{}invalidKey",
						},
						{
							Key: "`{}invalidKey.dot/dash",
						},
					},
					OverrideAffinity: &k8sv1.Affinity{
						NodeAffinity: &k8sv1.NodeAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: &k8sv1.NodeSelector{
								NodeSelectorTerms: []k8sv1.NodeSelectorTerm{
									{
										MatchExpressions: []k8sv1.NodeSelectorRequirement{
											{
												Key:      "`{}invalidKey.dot",
												Operator: "equal",
											},
											{
												Key:      "`{}invalidKey.dot/dash",
												Operator: "In",
											},
										},
										MatchFields: []k8sv1.NodeSelectorRequirement{
											{
												Key: "`{}invalidKey.dot",
											},
											{
												Key: "`{}invalidKey.dot/dash",
											},
										},
									},
								},
							},
							PreferredDuringSchedulingIgnoredDuringExecution: []k8sv1.PreferredSchedulingTerm{
								{
									Weight: 1,
									Preference: k8sv1.NodeSelectorTerm{
										MatchExpressions: []k8sv1.NodeSelectorRequirement{
											{
												Key:      "`{}invalidKey.dot",
												Operator: "in",
											},
											{
												Key:      "`{}invalidKey.dot/dash",
												Operator: "in",
											},
										},
										MatchFields: []k8sv1.NodeSelectorRequirement{
											{
												Key:      "`{}invalidKey.dot",
												Operator: "in",
											},
											{
												Key:      "`{}invalidKey.dot/dash",
												Operator: "in",
											},
										},
									},
								},
							},
						},
						PodAffinity: &k8sv1.PodAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: []k8sv1.PodAffinityTerm{
								{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"key": "`{}invalidKey",
										},
										MatchExpressions: []metav1.LabelSelectorRequirement{
											{
												Key:      "`{}invalidKey",
												Operator: "In",
												Values:   []string{""},
											},
										},
									},
								},
							},
							PreferredDuringSchedulingIgnoredDuringExecution: []k8sv1.WeightedPodAffinityTerm{
								{
									Weight: 1,
									PodAffinityTerm: k8sv1.PodAffinityTerm{
										NamespaceSelector: &metav1.LabelSelector{
											MatchLabels: nil,
											MatchExpressions: []metav1.LabelSelectorRequirement{
												{
													Key:      "`{}invalidKey",
													Operator: "In",
													Values:   []string{""},
												},
												{
													Key:      "`{}invalidKey2",
													Operator: "In",
													Values:   []string{""},
												},
											},
										},
									},
								},
							},
						},
						PodAntiAffinity: &k8sv1.PodAntiAffinity{
							RequiredDuringSchedulingIgnoredDuringExecution: []k8sv1.PodAffinityTerm{
								{
									LabelSelector: &metav1.LabelSelector{
										MatchLabels: map[string]string{
											"key": "validValue",
										},
										MatchExpressions: []metav1.LabelSelectorRequirement{
											{
												Key:      "`{}invalidKey",
												Operator: "In",
												Values:   []string{""},
											},
										},
									},
								},
							},
							PreferredDuringSchedulingIgnoredDuringExecution: []k8sv1.WeightedPodAffinityTerm{
								{
									Weight: 1,
									PodAffinityTerm: k8sv1.PodAffinityTerm{
										NamespaceSelector: &metav1.LabelSelector{
											MatchLabels: nil,
											MatchExpressions: []metav1.LabelSelectorRequirement{
												{
													Key:      "`{}invalidKey",
													Operator: "In",
													Values:   []string{""},
												},
												{
													Key:      "`{}invalidKey2",
													Operator: "In",
													Values:   []string{""},
												},
											},
										},
									},
								},
							},
						},
					},
				},
				path: field.NewPath("test"),
			},
			validateFunc: validateFailedPaths([]string{
				"test.appendTolerations[0]",
				"test.appendTolerations[1]",
				"test.overrideAffinity.nodeAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].preferences.matchFields[0].key",
				"test.overrideAffinity.nodeAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].preferences.matchFields[1].key",
				"test.overrideAffinity.nodeAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].preferences.matchExpressions[0].key",
				"test.overrideAffinity.nodeAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].preferences.matchExpressions[1].key",
				"test.overrideAffinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchFields[0].key",
				"test.overrideAffinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchFields[1].key",
				"test.overrideAffinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key",
				"test.overrideAffinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[1].key",
				"test.overrideAffinity.podAffinity.requiredDuringSchedulingIgnoredDuringExecution[0].labelSelector.matchLabels", // This one is from upstream.
				"test.overrideAffinity.podAffinity.requiredDuringSchedulingIgnoredDuringExecution[0].labelSelector.matchExpressions[0].key",
				"test.overrideAffinity.podAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].podAffinityTerm.namespaceSelector.matchExpressions[0].key",
				"test.overrideAffinity.podAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].podAffinityTerm.namespaceSelector.matchExpressions[1].key",
				"test.overrideAffinity.podAntiAffinity.requiredDuringSchedulingIgnoredDuringExecution[0].labelSelector.matchExpressions[0].key",
				"test.overrideAffinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].podAffinityTerm.namespaceSelector.matchExpressions[0].key",
				"test.overrideAffinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].podAffinityTerm.namespaceSelector.matchExpressions[1].key",
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validateAgentDeploymentCustomization(tt.args.customization, tt.args.path)
			tt.validateFunc(t, got)
		})
	}
}

func Test_validateAgentSchedulingCustomizationPriorityClass(t *testing.T) {
	preemptionNever := k8sv1.PreemptionPolicy("Never")
	preemptionInvalid := k8sv1.PreemptionPolicy("rancher")

	tests := []struct {
		name           string
		cluster        *v1.Cluster
		oldCluster     *v1.Cluster
		featureEnabled bool
		shouldSucceed  bool
	}{
		{
			name:           "empty priority class - feature enabled",
			cluster:        &v1.Cluster{},
			shouldSucceed:  true,
			featureEnabled: true,
		},
		{
			name:           "empty priority class - feature disabled",
			cluster:        &v1.Cluster{},
			shouldSucceed:  true,
			featureEnabled: true,
		},
		{
			name:           "valid priority class with default preemption",
			shouldSucceed:  true,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PriorityClass: &v1.PriorityClassSpec{
								Value: 123456,
							},
						},
					},
				},
			},
		},
		{
			name:           "valid priority class with custom preemption",
			shouldSucceed:  true,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PriorityClass: &v1.PriorityClassSpec{
								Value:            123456,
								PreemptionPolicy: &preemptionNever,
							},
						},
					},
				},
			},
		},
		{
			name:           "invalid priority class - value too large",
			shouldSucceed:  false,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PriorityClass: &v1.PriorityClassSpec{
								Value: 1234567891234567890,
							},
						},
					},
				},
			},
		},
		{
			name:           "invalid priority class - value too small",
			shouldSucceed:  false,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PriorityClass: &v1.PriorityClassSpec{
								Value: -1234567891234567890,
							},
						},
					},
				},
			},
		},
		{
			name:           "invalid priority class - preemption value invalid",
			shouldSucceed:  false,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PriorityClass: &v1.PriorityClassSpec{
								Value:            24321,
								PreemptionPolicy: &preemptionInvalid,
							},
						},
					},
				},
			},
		},
		{
			name:           "invalid priority class - feature is disabled",
			shouldSucceed:  false,
			featureEnabled: false,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PriorityClass: &v1.PriorityClassSpec{
								Value:            24321,
								PreemptionPolicy: &preemptionInvalid,
							},
						},
					},
				},
			},
		},
		{
			name:           "invalid update attempt - feature is disabled",
			shouldSucceed:  false,
			featureEnabled: false,
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PriorityClass: &v1.PriorityClassSpec{
								Value: 1234,
							},
						},
					},
				},
			},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PriorityClass: &v1.PriorityClassSpec{
								Value: 4321,
							},
						},
					},
				},
			},
		},
		{
			name:           "valid update attempt - feature is enabled",
			shouldSucceed:  false,
			featureEnabled: false,
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PriorityClass: &v1.PriorityClassSpec{
								Value: 1234,
							},
						},
					},
				},
			},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PriorityClass: &v1.PriorityClassSpec{
								Value: 4321,
							},
						},
					},
				},
			},
		},
		{
			name:           "valid update attempt - feature is disabled, but fields are unchanged",
			shouldSucceed:  true,
			featureEnabled: false,
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PriorityClass: &v1.PriorityClassSpec{
								Value: 1234,
							},
						},
					},
				},
			},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PriorityClass: &v1.PriorityClassSpec{
								Value: 1234,
							},
						},
					},
				},
			},
		},
		{
			name:           "valid update attempt - field is removed while feature is disabled",
			shouldSucceed:  true,
			featureEnabled: false,
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PriorityClass: &v1.PriorityClassSpec{
								Value: 1234,
							},
						},
					},
				},
			},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{},
			},
		},
	}

	t.Parallel()
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			a := provisioningAdmitter{
				featureCache: createMockFeatureCache(ctrl, common.SchedulingCustomizationFeatureName, tt.featureEnabled),
			}

			response, err := a.validatePriorityClass(tt.oldCluster, tt.cluster)
			assert.Equal(t, tt.shouldSucceed, response.Allowed)
			assert.NoError(t, err)
		})
	}
}

func Test_validateAgentSchedulingCustomizationPodDisruptionBudget(t *testing.T) {
	tests := []struct {
		name           string
		cluster        *v1.Cluster
		oldCluster     *v1.Cluster
		featureEnabled bool
		shouldSucceed  bool
	}{
		{
			name:           "no scheduling customization - feature enabled",
			cluster:        &v1.Cluster{},
			shouldSucceed:  true,
			featureEnabled: true,
		},
		{
			name:           "no scheduling customization - feature disabled",
			cluster:        &v1.Cluster{},
			shouldSucceed:  true,
			featureEnabled: false,
		},
		{
			name:           "invalid PDB configuration - negative min available integer",
			shouldSucceed:  false,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable: "-1",
							},
						},
					},
				},
			},
		},
		{
			name:           "invalid PDB configuration - negative max unavailable integer",
			shouldSucceed:  false,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MaxUnavailable: "-1",
							},
						},
					},
				},
			},
		},
		{
			name:           "invalid PDB configuration - both fields set",
			shouldSucceed:  false,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MaxUnavailable: "1",
								MinAvailable:   "1",
							},
						},
					},
				},
			},
		},
		{
			name:           "invalid PDB configuration - string passed to max unavailable",
			shouldSucceed:  false,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MaxUnavailable: "five",
							},
						},
					},
				},
			},
		},
		{
			name:           "invalid PDB configuration - string passed to min available",
			shouldSucceed:  false,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable: "five",
							},
						},
					},
				},
			},
		},
		{
			name:           "invalid PDB configuration - string with invalid percentage number set for min available",
			shouldSucceed:  false,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable: "5.5%",
							},
						},
					},
				},
			},
		},
		{
			name:           "invalid PDB configuration - string with invalid percentage number set for max unavailable",
			shouldSucceed:  false,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MaxUnavailable: "5.5%",
							},
						},
					},
				},
			},
		},
		{
			name:           "invalid PDB configuration - both set to zero",
			shouldSucceed:  false,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable:   "0",
								MaxUnavailable: "0",
							},
						},
					},
				},
			},
		},
		{
			name:           "valid PDB configuration - max unavailable set to integer",
			shouldSucceed:  true,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MaxUnavailable: "1",
							},
						},
					},
				},
			},
		},
		{
			name:           "valid PDB configuration - min available set to integer",
			shouldSucceed:  true,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable: "1",
							},
						},
					},
				},
			},
		},
		{
			name:           "valid PDB configuration - min available set to integer",
			shouldSucceed:  true,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable:   "1",
								MaxUnavailable: "0",
							},
						},
					},
				},
			},
		},
		{
			name:           "valid PDB configuration - max unavailable set to integer",
			shouldSucceed:  true,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable:   "0",
								MaxUnavailable: "1",
							},
						},
					},
				},
			},
		},
		{
			name:           "valid PDB configuration - max unavailable set to percentage",
			shouldSucceed:  true,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MaxUnavailable: "50%",
							},
						},
					},
				},
			},
		},
		{
			name:           "valid PDB configuration - min available set to percentage",
			shouldSucceed:  true,
			featureEnabled: true,
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable: "50%",
							},
						},
					},
				},
			},
		},
		{
			name:           "valid PDB configuration - updating from percentage to int",
			shouldSucceed:  true,
			featureEnabled: true,
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable: "50%",
							},
						},
					},
				},
			},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable: "1",
							},
						},
					},
				},
			},
		},
		{
			name:           "invalid PDB reconfiguration - feature is disabled",
			shouldSucceed:  false,
			featureEnabled: false,
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable: "50%",
							},
						},
					},
				},
			},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable: "1",
							},
						},
					},
				},
			},
		},
		{
			name:           "invalid PDB creation - feature is disabled",
			shouldSucceed:  false,
			featureEnabled: false,
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{},
			},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable: "1",
							},
						},
					},
				},
			},
		},
		{
			name:           "valid PDB reconfiguration - field is removed while feature is disabled",
			shouldSucceed:  true,
			featureEnabled: false,
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable: "50%",
							},
						},
					},
				},
			},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{},
			},
		},
		{
			name:           "valid update - field is unchanged while feature is disabled",
			shouldSucceed:  true,
			featureEnabled: false,
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable: "50%",
							},
						},
					},
				},
			},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					ClusterAgentDeploymentCustomization: &v1.AgentDeploymentCustomization{
						SchedulingCustomization: &v1.AgentSchedulingCustomization{
							PodDisruptionBudget: &v1.PodDisruptionBudgetSpec{
								MinAvailable: "50%",
							},
						},
					},
				},
			},
		},
	}

	t.Parallel()
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			a := provisioningAdmitter{
				featureCache: createMockFeatureCache(ctrl, common.SchedulingCustomizationFeatureName, tt.featureEnabled),
			}

			response, err := a.validatePodDisruptionBudget(tt.oldCluster, tt.cluster)
			assert.Equal(t, tt.shouldSucceed, response.Allowed)
			assert.NoError(t, err)
		})
	}
}

func createMockFeatureCache(ctrl *gomock.Controller, featureName string, enabled bool) *fake.MockNonNamespacedCacheInterface[*v3.Feature] {
	featureCache := fake.NewMockNonNamespacedCacheInterface[*v3.Feature](ctrl)
	featureCache.EXPECT().Get(featureName).DoAndReturn(func(string) (*v3.Feature, error) {
		return &v3.Feature{
			Spec: v3.FeatureSpec{
				Value: &enabled,
			},
		}, nil
	}).AnyTimes()
	return featureCache
}

func createMockSecretClient(ctrl *gomock.Controller) *fake.MockControllerInterface[*k8sv1.Secret, *k8sv1.SecretList] {
	secretClient := fake.NewMockControllerInterface[*k8sv1.Secret, *k8sv1.SecretList](ctrl)
	secretClient.EXPECT().Get("fleet-default", "credential-from-client", gomock.Any()).Return(
		&k8sv1.Secret{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "fleet-default",
				Name:      "credential-from-client",
			},
		}, nil).AnyTimes()
	secretClient.EXPECT().Get("fleet-default", "non-exist", gomock.Any()).Return(
		nil, apierrors.NewNotFound(k8sv1.Resource("secret"), "secret")).AnyTimes()

	return secretClient
}

func createMockSecretCache(ctrl *gomock.Controller) *fake.MockCacheInterface[*k8sv1.Secret] {
	secretCache := fake.NewMockCacheInterface[*k8sv1.Secret](ctrl)
	secretCache.EXPECT().Get("fleet-default", "credential-from-cache").Return(
		&k8sv1.Secret{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Secret",
				APIVersion: "v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Namespace: "fleet-default",
				Name:      "credential-from-cache",
			},
		}, nil).AnyTimes()
	secretCache.EXPECT().Get("fleet-default", "credential-from-client").Return(
		nil, apierrors.NewNotFound(k8sv1.Resource("secret"), "secret")).AnyTimes()
	secretCache.EXPECT().Get("fleet-default", "non-exist").Return(
		nil, apierrors.NewNotFound(k8sv1.Resource("secret"), "secret")).AnyTimes()

	return secretCache
}

func Test_validateS3Secret(t *testing.T) {
	tests := []struct {
		name          string
		cluster       *v1.Cluster
		oldCluster    *v1.Cluster
		shouldSucceed bool
	}{
		{
			name:          "valid - s3 credential is changed and exists",
			shouldSucceed: true,
			oldCluster: &v1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fleet-default",
					Name:      "testing-cluster",
				},
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							ETCD: &rkev1.ETCD{
								S3: &rkev1.ETCDSnapshotS3{
									CloudCredentialName: "old-secret",
								},
							},
						},
					},
				},
			},
			cluster: &v1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fleet-default",
					Name:      "testing-cluster",
				},
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							ETCD: &rkev1.ETCD{
								S3: &rkev1.ETCDSnapshotS3{
									CloudCredentialName: "credential-from-client",
								},
							},
						},
					},
				},
			},
		},
		{
			name:          "invalid - s3 credential is changed and does not exist",
			shouldSucceed: false,
			oldCluster: &v1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fleet-default",
					Name:      "testing-cluster",
				},
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							ETCD: &rkev1.ETCD{
								S3: &rkev1.ETCDSnapshotS3{
									CloudCredentialName: "old-secret",
								},
							},
						},
					},
				},
			},
			cluster: &v1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fleet-default",
					Name:      "testing-cluster",
				},
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							ETCD: &rkev1.ETCD{
								S3: &rkev1.ETCDSnapshotS3{
									CloudCredentialName: "non-exist",
								},
							},
						},
					},
				},
			},
		},
		{
			name:          "valid - s3 credential remains the same and exists",
			shouldSucceed: true,
			oldCluster: &v1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fleet-default",
					Name:      "testing-cluster",
				},
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							ETCD: &rkev1.ETCD{
								S3: &rkev1.ETCDSnapshotS3{
									CloudCredentialName: "credential-from-cache",
								},
							},
						},
					},
				},
			},
			cluster: &v1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fleet-default",
					Name:      "testing-cluster",
				},
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							ETCD: &rkev1.ETCD{
								S3: &rkev1.ETCDSnapshotS3{
									CloudCredentialName: "credential-from-cache",
								},
							},
						},
					},
				},
			},
		},
		{
			name:          "invalid - s3 credential does not exist",
			shouldSucceed: false,
			oldCluster:    &v1.Cluster{},
			cluster: &v1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fleet-default",
					Name:      "testing-cluster",
				},
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							ETCD: &rkev1.ETCD{
								S3: &rkev1.ETCDSnapshotS3{
									CloudCredentialName: "non-exist",
								},
							},
						},
					},
				},
			},
		},
		{
			name:          "valid - s3 credential can be found in cache",
			shouldSucceed: true,
			oldCluster:    &v1.Cluster{},
			cluster: &v1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fleet-default",
					Name:      "testing-cluster",
				},
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							ETCD: &rkev1.ETCD{
								S3: &rkev1.ETCDSnapshotS3{
									CloudCredentialName: "credential-from-cache",
								},
							},
						},
					},
				},
			},
		},
		{
			name:          "valid - s3 credential can be found in client",
			shouldSucceed: true,
			oldCluster:    &v1.Cluster{},
			cluster: &v1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fleet-default",
					Name:      "testing-cluster",
				},
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							ETCD: &rkev1.ETCD{
								S3: &rkev1.ETCDSnapshotS3{
									CloudCredentialName: "credential-from-client",
								},
							},
						},
					},
				},
			},
		},
		{
			name:          "valid - s3 credential is empty string",
			shouldSucceed: true,
			oldCluster:    &v1.Cluster{},
			cluster: &v1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "fleet-default",
					Name:      "testing-cluster",
				},
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						ClusterConfiguration: rkev1.ClusterConfiguration{
							ETCD: &rkev1.ETCD{
								S3: &rkev1.ETCDSnapshotS3{
									CloudCredentialName: "",
								},
							},
						},
					},
				},
			},
		},
	}

	t.Parallel()
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)
			a := provisioningAdmitter{
				secretClient: createMockSecretClient(ctrl),
				secretCache:  createMockSecretCache(ctrl),
			}

			response, err := a.validateS3Secret(tt.oldCluster, tt.cluster)
			assert.Equal(t, tt.shouldSucceed, response.Allowed)
			assert.NoError(t, err)
		})
	}
}
