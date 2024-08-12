package cluster

import (
	"fmt"
	"strings"
	"testing"

	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	k8sv1 "k8s.io/api/core/v1"
	v12 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
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
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
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
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
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
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
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
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
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
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
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
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
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
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
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
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
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
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
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
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
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
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
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
							Value: "a",
						},
					},
				},
			},
			oldCluster:    nil,
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
							Value: "a",
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
			name:    "CATTLE_AGENT_VAR_DIR present in old and new but different value",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
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
			name:    "CATTLE_AGENT_VAR_DIR present in old and migrated to new",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
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
			name:    "system-agent data dir changed",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
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
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
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
			name:    "provisioning data dir changed",
			request: &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{Operation: admissionv1.Update}},
			cluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
							DataDirectories: rkev1.DataDirectories{
								Provisioning: "a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
							DataDirectories: rkev1.DataDirectories{
								Provisioning: "b",
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
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
							DataDirectories: rkev1.DataDirectories{
								K8sDistro: "a",
							},
						},
					},
				},
			},
			oldCluster: &v1.Cluster{
				Spec: v1.ClusterSpec{
					RKEConfig: &v1.RKEConfig{
						RKEClusterSpecCommon: rkev1.RKEClusterSpecCommon{
							DataDirectories: rkev1.DataDirectories{
								K8sDistro: "b",
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
									LabelSelector: &v12.LabelSelector{
										MatchLabels: map[string]string{
											"key": "validValue",
										},
										MatchExpressions: []v12.LabelSelectorRequirement{
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
										NamespaceSelector: &v12.LabelSelector{
											MatchLabels: nil,
											MatchExpressions: []v12.LabelSelectorRequirement{
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
									LabelSelector: &v12.LabelSelector{
										MatchLabels: map[string]string{
											"key": "validValue",
										},
										MatchExpressions: []v12.LabelSelectorRequirement{
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
										NamespaceSelector: &v12.LabelSelector{
											MatchLabels: nil,
											MatchExpressions: []v12.LabelSelectorRequirement{
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
									LabelSelector: &v12.LabelSelector{
										MatchLabels: map[string]string{
											"key": "`{}invalidKey",
										},
										MatchExpressions: []v12.LabelSelectorRequirement{
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
										NamespaceSelector: &v12.LabelSelector{
											MatchLabels: nil,
											MatchExpressions: []v12.LabelSelectorRequirement{
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
									LabelSelector: &v12.LabelSelector{
										MatchLabels: map[string]string{
											"key": "validValue",
										},
										MatchExpressions: []v12.LabelSelectorRequirement{
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
										NamespaceSelector: &v12.LabelSelector{
											MatchLabels: nil,
											MatchExpressions: []v12.LabelSelectorRequirement{
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
