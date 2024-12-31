package node

import (
	"encoding/json"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

func TestAdmit(t *testing.T) {
	tests := []struct {
		name          string
		operation     admissionv1.Operation
		oldNode       v3.Node
		newNode       v3.Node
		expectAllowed bool
		wantErr       bool
	}{
		{
			name:      "Node in 'local' namespace cannot be deleted",
			operation: admissionv1.Delete,
			oldNode: v3.Node{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "local",
					Name:      "machine-123xyz",
				},
			},
			expectAllowed: false,
			wantErr:       false,
		},
		{
			name:      "Node in namespace other than 'local' can be deleted",
			operation: admissionv1.Delete,
			oldNode: v3.Node{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: "ns-123",
					Name:      "machine-123xyz",
				},
			},
			expectAllowed: true,
			wantErr:       false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := &Validator{
				admitter: admitter{},
			}
			oldNodeBytes, err := json.Marshal(tt.oldNode)
			assert.NoError(t, err)
			newNodeBytes, err := json.Marshal(tt.newNode)
			assert.NoError(t, err)

			admitters := v.Admitters()
			assert.Len(t, admitters, 1)

			res, err := admitters[0].Admit(&admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Object: runtime.RawExtension{
						Raw: newNodeBytes,
					},
					OldObject: runtime.RawExtension{
						Raw: oldNodeBytes,
					},
					Operation: tt.operation,
				},
			})
			assert.NoError(t, err)
			assert.Equal(t, tt.expectAllowed, res.Allowed)
		})
	}
}
