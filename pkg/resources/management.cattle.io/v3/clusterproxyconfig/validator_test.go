package clusterproxyconfig

import (
	"fmt"
	"testing"

	v3api "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	wranglerfake "github.com/rancher/wrangler/v3/pkg/generic/fake"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	admissionv1 "k8s.io/api/admission/v1"
	authenicationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
)

const (
	testNamespace = "testclusternamespace"
)

var (
	cpcGVR = metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "clusterproxyconfigs"}
	cpcGVK = metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "ClusterProxyConfig"}
)

func Test_admitter_Admit(t *testing.T) {
	tests := []struct {
		name          string
		alreadyExists bool
		allowed       bool
		wantErr       bool
	}{
		{
			name:          "create clusterproxyconfig when none exists",
			allowed:       true,
			alreadyExists: false,
		},
		{
			name:          "attempt to make more than one clusterproxyconfig",
			allowed:       false,
			alreadyExists: true,
		},
		{
			name:    "failed to list clusterproxyconfigs",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctrl := gomock.NewController(t)
			cpsCache := wranglerfake.NewMockCacheInterface[*v3api.ClusterProxyConfig](ctrl)
			cpsCache.EXPECT().List(testNamespace, labels.Everything()).DoAndReturn(func(_ string, _ labels.Selector) ([]*v3api.ClusterProxyConfig, error) {
				if tt.wantErr {
					return nil, fmt.Errorf("simulated list error")
				}
				if tt.alreadyExists {
					return []*v3api.ClusterProxyConfig{
						{
							Enabled: true,
						},
					}, nil
				}
				return nil, nil
			}).AnyTimes()
			a := &admitter{
				cpsCache: cpsCache,
			}
			resp, err := a.Admit(createRequest())
			if !tt.wantErr {
				require.NoError(t, err, "Admit returned an error")
				assert.Equal(t, tt.allowed, resp.Allowed)
			} else {
				require.Error(t, err)
				assert.Nil(t, resp)
			}
		})
	}
}

func createRequest() *admission.Request {
	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Kind:            cpcGVK,
			Resource:        cpcGVR,
			RequestKind:     &cpcGVK,
			RequestResource: &cpcGVR,
			Namespace:       testNamespace,
			Operation:       admissionv1.Create,
			UserInfo:        authenicationv1.UserInfo{Username: "test-user", UID: ""},
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
	}
	return &req
}
