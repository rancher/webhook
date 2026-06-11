package awsclusterstaticidentity

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/infrastructure.cluster.x-k8s.io/v1beta2/capautils"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
)

// mockSAR implements k8s.io/client-go/kubernetes/typed/authorization/v1.SubjectAccessReviewInterface for testing.
type mockSAR struct {
	allowed bool
	calls   int
}

func (m *mockSAR) Create(_ context.Context, _ *authorizationv1.SubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SubjectAccessReview, error) {
	m.calls++
	return &authorizationv1.SubjectAccessReview{
		Status: authorizationv1.SubjectAccessReviewStatus{Allowed: m.allowed},
	}, nil
}

func mustMarshal(t *testing.T, obj interface{}) []byte {
	t.Helper()
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("mustMarshal: %v", err)
	}
	return b
}

// makeIdentity builds an AWSClusterStaticIdentity. When annotated=true the
// Rancher Turtles source annotation is added, making it subject to credential
// access checks.
func makeIdentity(secretRef string, annotated bool) *infrav1.AWSClusterStaticIdentity {
	identity := &infrav1.AWSClusterStaticIdentity{
		ObjectMeta: metav1.ObjectMeta{Name: "my-identity"},
		Spec: infrav1.AWSClusterStaticIdentitySpec{
			SecretRef: secretRef,
		},
	}
	if annotated {
		identity.Annotations = map[string]string{
			capautils.AnnotationSourceID: "some-id",
		}
	}
	return identity
}

func makeRequest(t *testing.T, op admissionv1.Operation, newObj, oldObj *infrav1.AWSClusterStaticIdentity) *admission.Request {
	t.Helper()
	req := &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: op,
			Object:    runtime.RawExtension{Raw: mustMarshal(t, newObj)},
			UserInfo:  authenticationv1.UserInfo{Username: "test-user"},
		},
	}
	if oldObj != nil {
		req.OldObject = runtime.RawExtension{Raw: mustMarshal(t, oldObj)}
	}
	return req
}

func TestAWSClusterStaticIdentityValidator_Admit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name         string
		operation    admissionv1.Operation
		newObj       *infrav1.AWSClusterStaticIdentity
		oldObj       *infrav1.AWSClusterStaticIdentity
		sarAllowed   bool
		wantAllowed  bool
		wantSARCalls int
	}{
		// --- Annotation absent: always allowed, SAR never called ---
		{
			name:         "CREATE no annotation, allowed without SAR",
			operation:    admissionv1.Create,
			newObj:       makeIdentity("my-secret", false),
			wantAllowed:  true,
			wantSARCalls: 0,
		},
		{
			name:         "UPDATE no annotation, allowed without SAR",
			operation:    admissionv1.Update,
			newObj:       makeIdentity("new-secret", false),
			oldObj:       makeIdentity("old-secret", false),
			wantAllowed:  true,
			wantSARCalls: 0,
		},

		// --- Annotation present, empty secretRef ---
		{
			name:         "CREATE annotated, empty secretRef, allowed without SAR",
			operation:    admissionv1.Create,
			newObj:       makeIdentity("", true),
			wantAllowed:  true,
			wantSARCalls: 0,
		},

		// --- Annotation present, non-empty secretRef ---
		{
			name:         "CREATE annotated, user has access",
			operation:    admissionv1.Create,
			newObj:       makeIdentity("my-secret", true),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1,
		},
		{
			name:         "CREATE annotated, user lacks access",
			operation:    admissionv1.Create,
			newObj:       makeIdentity("my-secret", true),
			sarAllowed:   false,
			wantAllowed:  false,
			wantSARCalls: 1,
		},

		// --- UPDATE: secretRef unchanged → no SAR ---
		{
			name:         "UPDATE annotated, secretRef unchanged, allowed without SAR",
			operation:    admissionv1.Update,
			newObj:       makeIdentity("same-secret", true),
			oldObj:       makeIdentity("same-secret", true),
			sarAllowed:   false,
			wantAllowed:  true,
			wantSARCalls: 0,
		},

		// --- UPDATE: secretRef changed → SAR runs ---
		{
			name:         "UPDATE annotated, secretRef changed, user has access",
			operation:    admissionv1.Update,
			newObj:       makeIdentity("new-secret", true),
			oldObj:       makeIdentity("old-secret", true),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1,
		},
		{
			name:         "UPDATE annotated, secretRef changed, user lacks access",
			operation:    admissionv1.Update,
			newObj:       makeIdentity("new-secret", true),
			oldObj:       makeIdentity("old-secret", true),
			sarAllowed:   false,
			wantAllowed:  false,
			wantSARCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sar := &mockSAR{allowed: tt.sarAllowed}
			v := NewValidator(sar)

			resp, err := v.Admit(makeRequest(t, tt.operation, tt.newObj, tt.oldObj))
			if err != nil {
				t.Fatalf("Admit returned error: %v", err)
			}
			if resp.Allowed != tt.wantAllowed {
				t.Errorf("Allowed=%v, want %v (result: %+v)", resp.Allowed, tt.wantAllowed, resp.Result)
			}
			if sar.calls != tt.wantSARCalls {
				t.Errorf("SAR calls=%d, want %d", sar.calls, tt.wantSARCalls)
			}
		})
	}
}
