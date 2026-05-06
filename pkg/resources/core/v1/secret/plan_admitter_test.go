package secret

import (
	"encoding/json"
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	v1authentication "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestPlanAdmitterAdmit(t *testing.T) {
	const secretName = "test-plan-secret"
	const secretNamespace = "test-ns"

	secretGVR := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
	secretGVK := metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}

	tests := []struct {
		name       string
		secretType corev1.SecretType
		planData   []byte
		operation  admissionv1.Operation
		wantAdmit  bool
		wantError  bool
	}{
		{
			name:       "non-plan secret is allowed",
			secretType: corev1.SecretTypeOpaque,
			operation:  admissionv1.Create,
			wantAdmit:  true,
		},
		{
			name:       "plan secret with no plan data is allowed",
			secretType: machinePlanSecretType,
			operation:  admissionv1.Create,
			wantAdmit:  true,
		},
		{
			name:       "plan secret with valid plan is allowed on create",
			secretType: machinePlanSecretType,
			planData:   []byte(`{"files":[{"path":"/tmp/test","content":"aGVsbG8="}],"instructions":[{"name":"setup","command":"/bin/sh"}]}`),
			operation:  admissionv1.Create,
			wantAdmit:  true,
		},
		{
			name:       "plan secret with valid plan is allowed on update",
			secretType: machinePlanSecretType,
			planData:   []byte(`{"files":[{"path":"/tmp/test","content":"aGVsbG8="}],"instructions":[{"name":"setup","command":"/bin/sh"}]}`),
			operation:  admissionv1.Update,
			wantAdmit:  true,
		},
		{
			name:       "plan secret with invalid plan is rejected on create",
			secretType: machinePlanSecretType,
			planData:   []byte(`{not valid json`),
			operation:  admissionv1.Create,
			wantAdmit:  false,
		},
		{
			name:       "plan secret with invalid plan is rejected on update",
			secretType: machinePlanSecretType,
			planData:   []byte(`{not valid json`),
			operation:  admissionv1.Update,
			wantAdmit:  false,
		},
		{
			name:       "plan secret with empty plan data is allowed",
			secretType: machinePlanSecretType,
			planData:   []byte(`{}`),
			operation:  admissionv1.Create,
			wantAdmit:  true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			secret := corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: secretNamespace,
				},
				Type: test.secretType,
			}
			if test.planData != nil {
				secret.Data = map[string][]byte{
					"plan": test.planData,
				}
			}

			rawSecret, err := json.Marshal(secret)
			assert.NoError(t, err)

			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID:             "1",
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					Name:            secretName,
					Namespace:       secretNamespace,
					Operation:       test.operation,
					UserInfo:        v1authentication.UserInfo{Username: "test-user", UID: ""},
					Object:          runtime.RawExtension{Raw: rawSecret},
					OldObject:       runtime.RawExtension{},
				},
			}

			admitter := &planAdmitter{}
			response, err := admitter.Admit(&req)
			if test.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.wantAdmit, response.Allowed)
			}
		})
	}
}
