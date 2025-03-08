package cluster

import (
	"encoding/json"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	data2 "github.com/rancher/wrangler/v3/pkg/data"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
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
