package cluster

import (
	"encoding/json"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	data2 "github.com/rancher/wrangler/v3/pkg/data"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestAdmitPreserveUnknownFields(t *testing.T) {
	cluster := &v3.Cluster{}
	data, err := data2.Convert(cluster)
	assert.Nil(t, err)

	data.SetNested("test", "spec", "rancherKubernetesEngineConfig", "network", "aciNetworkProvider", "apicUserKeyTest")
	raw, err := json.Marshal(data)
	assert.Nil(t, err)

	request := &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Object: runtime.RawExtension{
				Raw: raw,
			},
			OldObject: runtime.RawExtension{
				Raw: raw,
			},
		},
	}

	m := ManagementClusterMutator{}

	request.Operation = admissionv1.Create
	response, err := m.Admit(request)
	assert.Nil(t, err)
	assert.Nil(t, response.Patch)

	request.Operation = admissionv1.Update
	response, err = m.Admit(request)
	assert.Nil(t, err)
	assert.Nil(t, response.Patch)
}

func TestMutateVersionManagement(t *testing.T) {
	tests := []struct {
		name      string
		cluster   *v3.Cluster
		operation admissionv1.Operation
		expect    bool
	}{
		{
			name:      "invalid operation",
			cluster:   &v3.Cluster{},
			operation: admissionv1.Delete,
			expect:    false,
		},
		{
			name: "invalid cluster",
			cluster: &v3.Cluster{
				Status: v3.ClusterStatus{
					Driver: "imported",
				},
			},
			operation: admissionv1.Update,
			expect:    false,
		},
		{
			name: "missing annotation",
			cluster: &v3.Cluster{
				Status: v3.ClusterStatus{
					Driver: "rke2",
				},
			},
			operation: admissionv1.Create,
			expect:    true,
		},
		{
			name: "empty value",
			cluster: &v3.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						VersionManagementAnno: "",
					},
				},
				Status: v3.ClusterStatus{
					Driver: "k3s",
				},
			},
			operation: admissionv1.Update,
			expect:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := &ManagementClusterMutator{}
			m.mutateVersionManagement(tt.cluster, tt.operation)
			if tt.expect {
				assert.Equal(t, tt.cluster.Annotations[VersionManagementAnno], "system-default")
			}
		})
	}
}
