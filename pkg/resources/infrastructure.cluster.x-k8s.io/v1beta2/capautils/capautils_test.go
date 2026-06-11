package capautils

import (
	"context"
	"fmt"
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// mockSAR implements authorizationv1.SubjectAccessReviewInterface for testing.
type mockSAR struct {
	allowed bool
	err     error
	calls   int
}

func (m *mockSAR) Create(_ context.Context, _ *authorizationv1.SubjectAccessReview, _ metav1.CreateOptions) (*authorizationv1.SubjectAccessReview, error) {
	m.calls++
	if m.err != nil {
		return nil, m.err
	}
	return &authorizationv1.SubjectAccessReview{
		Status: authorizationv1.SubjectAccessReviewStatus{Allowed: m.allowed},
	}, nil
}

func makeRequest(username string) *admission.Request {
	return &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UserInfo: authenticationv1.UserInfo{Username: username},
		},
	}
}

func TestHasSourceIDAnnotation(t *testing.T) {
	tests := []struct {
		name        string
		annotations map[string]string
		want        bool
	}{
		{
			name:        "annotation present with value",
			annotations: map[string]string{AnnotationSourceID: "some-id"},
			want:        true,
		},
		{
			name:        "annotation present but empty value",
			annotations: map[string]string{AnnotationSourceID: ""},
			want:        false,
		},
		{
			name:        "annotation absent",
			annotations: map[string]string{"other-key": "value"},
			want:        false,
		},
		{
			name:        "no annotations",
			annotations: nil,
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := &metav1.ObjectMeta{Annotations: tt.annotations}
			if got := HasSourceIDAnnotation(obj); got != tt.want {
				t.Errorf("HasSourceIDAnnotation() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCheckSecretAccess(t *testing.T) {
	tests := []struct {
		name        string
		secretName  string
		sarAllowed  bool
		sarErr      error
		wantAllowed bool
		wantErr     bool
		wantCalls   int
	}{
		{
			name:        "access granted",
			secretName:  "my-secret",
			sarAllowed:  true,
			wantAllowed: true,
			wantCalls:   1,
		},
		{
			name:        "access denied",
			secretName:  "my-secret",
			sarAllowed:  false,
			wantAllowed: false,
			wantCalls:   1,
		},
		{
			name:       "SAR call fails",
			secretName: "my-secret",
			sarErr:     fmt.Errorf("connection refused"),
			wantErr:    true,
			wantCalls:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sar := &mockSAR{allowed: tt.sarAllowed, err: tt.sarErr}
			resp, err := CheckSecretAccess(makeRequest("test-user"), tt.secretName, sar)

			if (err != nil) != tt.wantErr {
				t.Fatalf("CheckSecretAccess() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr {
				if resp.Allowed != tt.wantAllowed {
					t.Errorf("Allowed=%v, want %v (result: %+v)", resp.Allowed, tt.wantAllowed, resp.Result)
				}
			}
			if sar.calls != tt.wantCalls {
				t.Errorf("SAR calls=%d, want %d", sar.calls, tt.wantCalls)
			}
		})
	}
}
