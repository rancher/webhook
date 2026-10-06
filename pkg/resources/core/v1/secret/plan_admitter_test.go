package secret

import (
	"encoding/json"
	"net/http"
	"testing"

	planv1alpha1 "github.com/rancher/rancher/pkg/plan/api/plan.cattle.io/v1alpha1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

			// The API server sends the object being replaced with every update.
			oldObject := runtime.RawExtension{}
			if test.operation == admissionv1.Update {
				oldObject.Raw = rawSecret
			}

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
					OldObject:       oldObject,
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

// The labels tying a machine-plan secret to its cluster and machine can be added, but not changed or
// removed once set. Each is compared with the same key on the old and new secret, so a secret whose
// machine and cluster are named differently, which is nearly every one, updates freely.
func TestPlanAdmitterAdmit_ImmutableLabels(t *testing.T) {
	labeled := func() map[string]string {
		return map[string]string{
			planv1alpha1.ClusterLifecycleGroupLabel: "management.cattle.io",
			planv1alpha1.ClusterLifecycleKindLabel:  "Cluster",
			planv1alpha1.ClusterLifecycleNameLabel:  "c-abc",
			planv1alpha1.MachineLifecycleGroupLabel: "cluster.x-k8s.io",
			planv1alpha1.MachineLifecycleKindLabel:  "Machine",
			planv1alpha1.MachineLifecycleNameLabel:  "machine-1",
			rkeClusterNameLabel:                     "c-abc",
			"unrelated":                             "a",
		}
	}

	type testCase struct {
		name        string
		secretType  corev1.SecretType
		operation   admissionv1.Operation
		old, new    map[string]string
		wantAllowed bool
		wantMessage string
	}
	tests := []testCase{
		{name: "nothing changed", operation: admissionv1.Update, old: labeled(), new: labeled(), wantAllowed: true},
		{
			name: "an unrelated label changed", operation: admissionv1.Update, old: labeled(),
			new:         func() map[string]string { l := labeled(); l["unrelated"] = "b"; return l }(),
			wantAllowed: true,
		},
		{name: "the labels added", operation: admissionv1.Update, old: map[string]string{"unrelated": "a"}, new: labeled(), wantAllowed: true},
		{name: "a secret created with them", operation: admissionv1.Create, new: labeled(), wantAllowed: true},
		{
			name: "a secret of another type", secretType: corev1.SecretTypeOpaque, operation: admissionv1.Update, old: labeled(),
			new:         map[string]string{},
			wantAllowed: true,
		},
	}
	for _, key := range immutablePlanLabels {
		tests = append(tests,
			testCase{
				name: "changing " + key, operation: admissionv1.Update, old: labeled(),
				new:         func() map[string]string { l := labeled(); l[key] = "other"; return l }(),
				wantMessage: "machine-plan secret test-ns/test-plan-secret: label " + key + " cannot be changed once set",
			},
			testCase{
				name: "removing " + key, operation: admissionv1.Update, old: labeled(),
				new:         func() map[string]string { l := labeled(); delete(l, key); return l }(),
				wantMessage: "machine-plan secret test-ns/test-plan-secret: label " + key + " cannot be removed once set",
			},
			testCase{
				name: "emptying " + key, operation: admissionv1.Update, old: labeled(),
				new:         func() map[string]string { l := labeled(); l[key] = ""; return l }(),
				wantMessage: "label " + key + " cannot be changed once set",
			},
		)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secretType := tt.secretType
			if secretType == "" {
				secretType = machinePlanSecretType
			}
			raw := func(labels map[string]string) []byte {
				data, err := json.Marshal(corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Name: "test-plan-secret", Namespace: "test-ns", Labels: labels},
					Type:       secretType,
				})
				require.NoError(t, err)
				return data
			}

			request := &admission.Request{AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: tt.operation,
				Object:    runtime.RawExtension{Raw: raw(tt.new)},
			}}
			if tt.operation == admissionv1.Update {
				request.OldObject = runtime.RawExtension{Raw: raw(tt.old)}
			}

			response, err := (&planAdmitter{}).Admit(request)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, response.Allowed)
			if !tt.wantAllowed {
				require.NotNil(t, response.Result)
				assert.Equal(t, int32(http.StatusBadRequest), response.Result.Code)
				assert.Contains(t, response.Result.Message, tt.wantMessage)
			}
		})
	}
}
