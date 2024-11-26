package namespace

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const testNs = "test-ns"

func TestRequestLimitAdmitter(t *testing.T) {
	tests := []struct {
		name             string
		operationType    v1.Operation
		limitsAnnotation string
		wantAllowed      bool
	}{
		{
			name:             "create ns within resource limits",
			operationType:    v1.Create,
			limitsAnnotation: `{"limitsCpu": "500m", "requestsCpu": "100m", "limitsMemory": "128Mi", "requestsMemory": "64Mi"}`,
			wantAllowed:      true,
		},
		{
			name:             "create ns exceeds resource limits",
			operationType:    v1.Create,
			limitsAnnotation: `{"limitsCpu": "200m", "limitsMemory": "256Mi", "requestsCpu": "1", "requestsMemory": "1Gi"}`,
			wantAllowed:      false,
		},
		{
			name:             "create ns invalid JSON in annotation",
			operationType:    v1.Create,
			limitsAnnotation: `invalid-json`,
			wantAllowed:      false,
		},
		{
			name:             "create ns no request annotation",
			operationType:    v1.Create,
			limitsAnnotation: "",
			wantAllowed:      true,
		},
		{
			name:             "update ns within resource limits",
			operationType:    v1.Update,
			limitsAnnotation: `{"limitsCpu": "500m", "requestsCpu": "100m", "limitsMemory": "128Mi", "requestsMemory": "64Mi"}`,
			wantAllowed:      true,
		},
		{
			name:             "update ns exceeds resource limits",
			operationType:    v1.Update,
			limitsAnnotation: `{"limitsCpu": "200m", "limitsMemory": "256Mi", "requestsCpu": "1", "requestsMemory": "1Gi"}`,
			wantAllowed:      false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			admitter := requestLimitAdmitter{}
			request, err := createRequestLimitRequest(test.limitsAnnotation, test.operationType)
			if test.operationType == v1.Update {
				request.AdmissionRequest.OldObject.Raw, err = json.Marshal(corev1.Namespace{
					ObjectMeta: metav1.ObjectMeta{
						Name: testNs,
					},
				})
			}
			assert.NoError(t, err)
			response, err := admitter.Admit(request)
			assert.NoError(t, err)
			assert.Equal(t, test.wantAllowed, response.Allowed)
		})
	}
}

func createRequestLimitRequest(limitsAnnotation string, operation v1.Operation) (*admission.Request, error) {
	gvk := metav1.GroupVersionKind{Version: "v1", Kind: "Namespace"}
	gvr := metav1.GroupVersionResource{Version: "v1", Resource: "namespace"}

	ns := corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: testNs,
		},
	}
	if limitsAnnotation != "" {
		ns.Annotations = map[string]string{
			resourceLimitAnnotation: limitsAnnotation,
		}
	}

	req := &admission.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:             "",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Name:            ns.Name,
			Operation:       operation,
			UserInfo:        authenticationv1.UserInfo{Username: "test-user", UID: ""},
		},
		Context: context.Background(),
	}

	var err error
	req.Object.Raw, err = json.Marshal(ns)
	if err != nil {
		return nil, err
	}
	return req, nil
}
