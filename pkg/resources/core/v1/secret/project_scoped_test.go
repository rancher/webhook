package secret

import (
	"encoding/json"
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	v1authentication "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestAdmitValidatesProjectScopedSecrets(t *testing.T) {
	t.Parallel()
	validSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mystery",
			Namespace: "p-abcde",
			Labels: map[string]string{
				projectScopedLabel: "original",
			},
			Annotations: map[string]string{
				projectIDAnnotation: "c-abcde:p-abcde",
			},
		},
	}
	validSecretUpdate := validSecret.DeepCopy()
	validSecretUpdate.StringData = map[string]string{"hello": "world"}
	validator := NewProjectScopedValidator()

	tests := []struct {
		name      string
		operation admissionv1.Operation
		secret    *v1.Secret
		update    *v1.Secret
		wantAdmit bool
	}{
		{
			name:      "create a regular project scoped secret",
			operation: admissionv1.Create,
			secret:    validSecret,
			wantAdmit: true,
		},
		{
			name:      "update a regular project scoped secret",
			operation: admissionv1.Update,
			secret:    validSecret,
			update:    validSecretUpdate,
			wantAdmit: true,
		},
		{
			name:      "fail to create a project scoped secret with no cluster id in annotation",
			operation: admissionv1.Create,
			secret: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "mystery",
					Namespace: "p-abcde",
					Labels: map[string]string{
						projectScopedLabel: "original",
					},
					Annotations: map[string]string{
						projectIDAnnotation: "  ",
					},
				},
			},
			wantAdmit: false,
		},
		{
			name:      "fail to update the project-scoped label",
			operation: admissionv1.Update,
			secret:    validSecret,
			update: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "mystery",
					Namespace: "p-abcde",
					Labels:    map[string]string{}, // now missing
					Annotations: map[string]string{
						projectIDAnnotation: "c-abcde:p-abcde",
					},
				},
			},
			wantAdmit: false,
		},
		{
			name:      "fail to update the project-scoped annotation",
			operation: admissionv1.Update,
			secret:    validSecret,
			update: &v1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "mystery",
					Namespace: "p-abcde",
					Labels: map[string]string{
						projectScopedLabel: "original",
					},
					Annotations: map[string]string{}, // now missing
				},
			},
			wantAdmit: false,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			secretGVR := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "secrets"}
			secretGVK := metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "Secret"}
			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID:             "2",
					Kind:            secretGVK,
					Resource:        secretGVR,
					RequestKind:     &secretGVK,
					RequestResource: &secretGVR,
					Name:            "mystery",
					Namespace:       test.secret.Namespace,
					Operation:       test.operation,
					UserInfo:        v1authentication.UserInfo{Username: "test-user", UID: ""},
					Object:          runtime.RawExtension{},
					OldObject:       runtime.RawExtension{},
				},
			}

			var err error
			req.Object.Raw, err = json.Marshal(test.secret)
			require.NoError(t, err)

			if test.update != nil {
				req.OldObject.Raw, err = json.Marshal(test.update)
				require.NoError(t, err)
			}

			admitters := validator.Admitters()
			assert.Len(t, admitters, 1)
			response, err := admitters[0].Admit(&req)
			require.NoError(t, err)
			require.Equal(t, test.wantAdmit, response.Allowed)
		})
	}
}

func TestAdmitFailsWhenProjectScopedSecretRequestsAreBad(t *testing.T) {
	t.Parallel()
	validator := NewProjectScopedValidator()

	tests := []struct {
		name      string
		operation admissionv1.Operation
		wantError bool
	}{
		{
			name:      "create request",
			operation: admissionv1.Create,
			wantError: true,
		},
		{
			name:      "update request",
			operation: admissionv1.Update,
			wantError: true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			// The request contains too little information.
			request := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: test.operation,
				},
			}
			admitters := validator.Admitters()
			assert.Len(t, admitters, 1)
			response, err := admitters[0].Admit(&request)
			require.Error(t, err)
			require.Nil(t, response)
		})
	}
}
