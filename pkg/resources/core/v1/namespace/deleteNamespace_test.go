package namespace

import (
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
)

func Test_Admit(t *testing.T) {
	tests := []struct {
		name          string
		namespaceName string
		operationType admissionv1.Operation
		wantAllowed   bool
		wantErr       bool
	}{
		{
			name:          "Allow creating namespace",
			namespaceName: "local",
			operationType: admissionv1.Create,
			wantAllowed:   true,
			wantErr:       false,
		},
		{
			name:          "Prevent deletion of 'local' namespace",
			namespaceName: "local",
			operationType: admissionv1.Delete,
			wantAllowed:   false,
			wantErr:       true,
		},
		{
			name:          "Prevent deletion of 'fleet-local' namespace",
			namespaceName: "fleet-local",
			operationType: admissionv1.Delete,
			wantAllowed:   false,
			wantErr:       true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			d := deleteNamespaceAdmitter{}
			request := createRequest(test.name, test.namespaceName, test.operationType)
			response, err := d.Admit(request)
			if test.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.wantAllowed, response.Allowed)
			}
		})
	}
}

func createRequest(name, namespaceName string, operation admissionv1.Operation) *admission.Request {
	return &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Name:      name,
			Namespace: namespaceName,
			Operation: operation,
		},
	}
}
