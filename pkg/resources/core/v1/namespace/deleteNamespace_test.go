package namespace

import (
	"encoding/json"
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func Test_Admit(t *testing.T) {
	tests := []struct {
		name          string
		namespaceName string
		operationType admissionv1.Operation
		malformed     bool
		wantAllowed   bool
		wantErr       bool
	}{
		{
			name:          "Allow creating namespace",
			namespaceName: "local",
			operationType: admissionv1.Create,
			wantAllowed:   true,
		},
		{
			name:          "Allow updating namespace",
			namespaceName: "local",
			operationType: admissionv1.Update,
			wantAllowed:   true,
		},
		{
			name:          "Prevent deletion of 'local' namespace",
			namespaceName: "local",
			operationType: admissionv1.Delete,
			wantAllowed:   false,
		},
		{
			name:          "Prevent deletion of 'fleet-local' namespace",
			namespaceName: "fleet-local",
			operationType: admissionv1.Delete,
			wantAllowed:   false,
		},
		{
			name:          "Allow deletion of an unprotected namespace",
			namespaceName: "customer-app",
			operationType: admissionv1.Delete,
			wantAllowed:   true,
		},
		{
			name:          "Error on a malformed delete request",
			namespaceName: "local",
			operationType: admissionv1.Delete,
			malformed:     true,
			wantErr:       true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			d := deleteNamespaceAdmitter{}
			request := createRequest(t, test.namespaceName, test.operationType, test.malformed)
			response, err := d.Admit(request)
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.wantAllowed, response.Allowed)
		})
	}
}

func createRequest(t *testing.T, namespaceName string, operation admissionv1.Operation, malformed bool) *admission.Request {
	t.Helper()

	raw := []byte(`{"invalid`)
	if !malformed {
		ns := corev1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: namespaceName,
			},
		}
		var err error
		raw, err = json.Marshal(ns)
		require.NoError(t, err)
	}

	request := &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Name:      namespaceName,
			Operation: operation,
		},
	}
	// Namespaces are cluster scoped, so the object is only sent in OldObject on delete.
	if operation == admissionv1.Delete {
		request.OldObject = runtime.RawExtension{Raw: raw}
	} else {
		request.Object = runtime.RawExtension{Raw: raw}
	}

	return request
}
