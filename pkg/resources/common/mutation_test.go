package common

import (
	"testing"

	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestSetCreatorIDAnnotation(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		cluster     v1.Cluster
		annotations map[string]string
	}{
		{
			name:     "add creatorID to nil annotations",
			username: "testUser",
			cluster:  v1.Cluster{},
			annotations: map[string]string{
				CreatorIDAnn: "testUser",
			},
		},
		{
			name:     "add creatorID to existing annotations",
			username: "testUser",
			cluster: v1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"existingAnno": "test",
					},
				},
			},
			annotations: map[string]string{
				"existingAnno": "test",
				CreatorIDAnn:   "testUser",
			},
		},
		{
			name:     "don't add creatorID if noCreatorRBAC is set",
			username: "testUser",
			cluster: v1.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						NoCreatorRBACAnn: "true",
					},
				},
			},
			annotations: map[string]string{
				NoCreatorRBACAnn: "true",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UserInfo: authenticationv1.UserInfo{
						Username: test.username,
					},
				},
			}
			SetCreatorIDAnnotation(&req, &test.cluster)
			assert.Equal(t, test.annotations, test.cluster.GetAnnotations())
		})
	}
}
