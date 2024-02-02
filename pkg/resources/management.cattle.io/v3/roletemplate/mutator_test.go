package roletemplate

import (
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
)

func TestAdmit(t *testing.T) {
	tests := map[string]struct {
		rtBytes      []byte
		wantResponse *admissionv1.AdmissionResponse
	}{
		"rt with empty resourceNames should be patched": {
			rtBytes: []byte(`{
				"description":"",
				"builtin":false,
				"external":false,
				"hidden":false,
				"metadata": {"creationTimestamp":null},
				"rules":[
					{
						"apiGroups":[""],
						"resources":["pods"],
						"verbs":["get"],
						"resourceNames":[]
					}
				]
			}`),
			wantResponse: &admissionv1.AdmissionResponse{
				Allowed: true,
				PatchType: func() *admissionv1.PatchType {
					pt := admissionv1.PatchTypeJSONPatch
					return &pt
				}(),
				Patch: []byte(`[{"op":"remove","path":"/rules/0/resourceNames"}]`),
			},
		},
		"rt should not be patched": {
			rtBytes: []byte(`{
				"description":"",
				"builtin":false,
				"external":false,
				"hidden":false,
				"metadata": {"creationTimestamp":null},
				"rules":[
					{
						"apiGroups":[""],
						"resources":["pods"],
						"verbs":["get"]
					}
				]
			}`),
			wantResponse: &admissionv1.AdmissionResponse{
				Allowed: true,
			},
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			m := NewMutator()
			req := &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Object: runtime.RawExtension{
						Raw: test.rtBytes,
					},
				},
			}
			response, err := m.Admit(req)
			assert.NoError(t, err)
			assert.Equal(t, response, test.wantResponse)
		})
	}
}
