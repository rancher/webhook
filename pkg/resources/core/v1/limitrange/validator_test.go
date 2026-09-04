package limitrange

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	testNamespace = "test-ns"
)

func TestLimitRangeValidator(t *testing.T) {
	t.Parallel()

	rqOld := makeObject("rq", testNamespace, nil, []corev1.LimitRangeItem{})
	rq := makeObject("rq", testNamespace, nil, []corev1.LimitRangeItem{})
	rqManaged := makeObject("rqmanaged", testNamespace, markerLabels(), []corev1.LimitRangeItem{})

	tests := []struct {
		name        string
		operation   admissionv1.Operation
		subresource string
		oldRQ       *corev1.LimitRange
		newRQ       *corev1.LimitRange
		wantAllowed bool
		wantErr     bool
		system      bool
	}{
		// --- CREATE ---
		{
			name:        "create unmanaged is allowed",
			operation:   admissionv1.Create,
			newRQ:       rq,
			wantAllowed: true,
		},
		{
			name:        "create managed is denied",
			operation:   admissionv1.Create,
			newRQ:       rqManaged,
			wantAllowed: false,
		},
		// --- UPDATE ---
		{
			name:        "update unmanaged is allowed",
			operation:   admissionv1.Update,
			oldRQ:       rqOld,
			newRQ:       rq,
			wantAllowed: true,
		},
		{
			name:        "update promotion to managed is denied",
			operation:   admissionv1.Update,
			oldRQ:       rq,
			newRQ:       rqManaged,
			wantAllowed: false,
		},
		{
			name:        "update demotion to unmanaged is denied",
			operation:   admissionv1.Update,
			oldRQ:       rqManaged,
			newRQ:       rq,
			wantAllowed: false,
		},
		{
			name:        "status update of managed is allowed",
			operation:   admissionv1.Update,
			subresource: "status",
			oldRQ:       rqManaged,
			newRQ:       rqManaged,
			wantAllowed: true,
		},
		{
			name:        "status update promotion to managed is denied",
			operation:   admissionv1.Update,
			subresource: "status",
			oldRQ:       rq,
			newRQ:       rqManaged,
			wantAllowed: false,
		},
		{
			name:        "status update demotion to unmanaged is denied",
			operation:   admissionv1.Update,
			subresource: "status",
			oldRQ:       rqManaged,
			newRQ:       rq,
			wantAllowed: false,
		},
		// --- DELETE ---
		{
			name:        "delete unmanaged is allowed",
			operation:   admissionv1.Delete,
			oldRQ:       rq,
			wantAllowed: true,
		},
		{
			name:        "delete managed is denied",
			operation:   admissionv1.Delete,
			oldRQ:       rqManaged,
			wantAllowed: false,
		},
		{
			name:        "delete managed is allowed to system controller",
			operation:   admissionv1.Delete,
			oldRQ:       rqManaged,
			wantAllowed: true,
			system:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := NewValidator()
			assert.Len(t, v.Admitters(), 1)

			req, err := createRequest(tt.oldRQ, tt.newRQ, tt.operation, tt.subresource)
			assert.NoError(t, err)
			if tt.system {
				req = systemController(req)
			}

			resp, err := v.Admitters()[0].Admit(req)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, resp.Allowed)
		})
	}
}

func TestLimitRangeValidatingWebhookIncludesStatusSubresource(t *testing.T) {
	t.Parallel()

	webhooks := NewValidator().ValidatingWebhook(admissionregistrationv1.WebhookClientConfig{})
	assert.Len(t, webhooks, 1)
	assert.Len(t, webhooks[0].Rules, 1)
	assert.Equal(t, []string{"limitranges", "limitranges/status"}, webhooks[0].Rules[0].Resources)
}

// systemController adds the kubernetes namespace controller user to the request
func systemController(request *admission.Request) *admission.Request {
	newRq := *request
	newRq.UserInfo.Username = kubernetesNamespaceController
	return &newRq
}

// createRequest builds an admission.Request for a LimitRange operation.
func createRequest(oldObject, newObject *corev1.LimitRange, operation admissionv1.Operation, subresource string) (*admission.Request, error) {
	gvk := metav1.GroupVersionKind{Group: "", Version: "v1", Kind: "LimitRange"}
	gvr := metav1.GroupVersionResource{Group: "", Version: "v1", Resource: "limitranges"}
	req := &admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Operation:       operation,
			SubResource:     subresource,
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
	}
	if newObject != nil {
		raw, err := json.Marshal(newObject)
		if err != nil {
			return nil, err
		}
		req.Object.Raw = raw
	}
	if oldObject != nil {
		raw, err := json.Marshal(oldObject)
		if err != nil {
			return nil, err
		}
		req.OldObject.Raw = raw
	}
	return req, nil
}

// makeObject builds a LimitRange for testing purposes.
func makeObject(name, namespace string, labels map[string]string, limits []corev1.LimitRangeItem) *corev1.LimitRange {
	return &corev1.LimitRange{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    labels,
		},
		Spec: corev1.LimitRangeSpec{
			Limits: limits,
		},
	}
}

// markerLabels returns the label map that identifies a Rancher-managed LimitRange.
func markerLabels() map[string]string {
	return map[string]string{defaultLimitRangeLabel: "true"}
}
