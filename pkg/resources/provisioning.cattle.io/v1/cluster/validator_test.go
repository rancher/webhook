package cluster

import (
	"strings"
	"testing"

	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	admissionv1 "k8s.io/api/admission/v1"
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
			clusterName:      "-cluster-name",
			clusterNamespace: "fleet-default",
			clusterExists:    true,
			want:             false,
		},
		{
			name:             "name cannot end with hyphen",
			clusterName:      "cluster-name-",
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
		{
			name:             "name length is 1 character",
			clusterName:      "a",
			clusterNamespace: "fleet-default",
			clusterExists:    false,
			want:             true,
		},
		{
			name:             "name length is 0 characters",
			clusterName:      "",
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
