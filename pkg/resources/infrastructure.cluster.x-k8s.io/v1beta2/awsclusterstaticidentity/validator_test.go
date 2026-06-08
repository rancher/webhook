package awsclusterstaticidentity

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	infrav1 "sigs.k8s.io/cluster-api-provider-aws/v2/api/v1beta2"
)

// mockSAR implements authorizationv1client.SubjectAccessReviewInterface for testing.
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

func makeIdentity(secretRef string) *infrav1.AWSClusterStaticIdentity {
	return &infrav1.AWSClusterStaticIdentity{
		ObjectMeta: metav1.ObjectMeta{Name: "my-identity"},
		Spec: infrav1.AWSClusterStaticIdentitySpec{
			SecretRef: secretRef,
		},
	}
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
	tests := []struct {
		name         string
		operation    admissionv1.Operation
		newObj       *infrav1.AWSClusterStaticIdentity
		oldObj       *infrav1.AWSClusterStaticIdentity
		sarAllowed   bool
		wantAllowed  bool
		wantSARCalls int
	}{
		{
			name:         "CREATE with secretRef, user has access",
			operation:    admissionv1.Create,
			newObj:       makeIdentity("my-secret"),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1,
		},
		{
			name:         "CREATE with secretRef, user lacks access",
			operation:    admissionv1.Create,
			newObj:       makeIdentity("my-secret"),
			sarAllowed:   false,
			wantAllowed:  false,
			wantSARCalls: 1,
		},
		{
			name:         "CREATE with empty secretRef, allowed without SAR",
			operation:    admissionv1.Create,
			newObj:       makeIdentity(""),
			sarAllowed:   false,
			wantAllowed:  true,
			wantSARCalls: 0,
		},
		{
			name:         "UPDATE secretRef unchanged, allowed without SAR",
			operation:    admissionv1.Update,
			newObj:       makeIdentity("same-secret"),
			oldObj:       makeIdentity("same-secret"),
			sarAllowed:   false,
			wantAllowed:  true,
			wantSARCalls: 0,
		},
		{
			name:         "UPDATE secretRef changed, SAR performed, allowed",
			operation:    admissionv1.Update,
			newObj:       makeIdentity("new-secret"),
			oldObj:       makeIdentity("old-secret"),
			sarAllowed:   true,
			wantAllowed:  true,
			wantSARCalls: 1,
		},
		{
			name:         "UPDATE secretRef changed, SAR denied",
			operation:    admissionv1.Update,
			newObj:       makeIdentity("new-secret"),
			oldObj:       makeIdentity("old-secret"),
			sarAllowed:   false,
			wantAllowed:  false,
			wantSARCalls: 1,
		},
	}

	t.Parallel()
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
