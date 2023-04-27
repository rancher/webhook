package feature

import (
	"context"
	"encoding/json"
	"testing"

	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/pointer"

	"github.com/rancher/webhook/pkg/admission"
)

type test struct {
	name       string
	operation  admissionv1.Operation
	feature    apisv3.Feature
	oldFeature apisv3.Feature
	allowed    bool
	wantErr    bool
}

func TestValidator_Admit(t *testing.T) {
	tests := []test{
		{
			name:      "Update multi-cluster-management featuer from false to true-should be allowed",
			operation: admissionv1.Update,
			feature: apisv3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: "multi-cluster-management",
				},
				Spec: apisv3.FeatureSpec{
					Value: pointer.Bool(true),
				},
				Status: apisv3.FeatureStatus{
					Dynamic:     true,
					Default:     false,
					LockedValue: nil,
				},
			},
			oldFeature: apisv3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: "multi-cluster-management",
				},
				Spec: apisv3.FeatureSpec{
					Value: pointer.Bool(false),
				},
				Status: apisv3.FeatureStatus{
					Dynamic:     true,
					Default:     false,
					LockedValue: nil,
				},
			},
			allowed: true,
			wantErr: false,
		},
		{
			name:      "Update multi-cluster-management featuer from nil to true-should be allowed",
			operation: admissionv1.Update,
			feature: apisv3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: "multi-cluster-management",
				},
				Spec: apisv3.FeatureSpec{
					Value: pointer.Bool(true),
				},
				Status: apisv3.FeatureStatus{
					Dynamic:     true,
					Default:     false,
					LockedValue: nil,
				},
			},
			oldFeature: apisv3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: "multi-cluster-management",
				},
				Spec: apisv3.FeatureSpec{
					Value: nil,
				},
				Status: apisv3.FeatureStatus{
					Dynamic:     true,
					Default:     false,
					LockedValue: nil,
				},
			},
			allowed: true,
			wantErr: false,
		},
		{
			name:      "Update multi-cluster-management featuer from true to false-should not be allowed",
			operation: admissionv1.Update,
			feature: apisv3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: "multi-cluster-management",
				},
				Spec: apisv3.FeatureSpec{
					Value: pointer.Bool(false),
				},
				Status: apisv3.FeatureStatus{
					Dynamic:     true,
					Default:     false,
					LockedValue: nil,
				},
			},
			oldFeature: apisv3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: "multi-cluster-management",
				},
				Spec: apisv3.FeatureSpec{
					Value: pointer.Bool(true),
				},
				Status: apisv3.FeatureStatus{
					Dynamic:     true,
					Default:     false,
					LockedValue: nil,
				},
			},
			allowed: false,
			wantErr: false,
		},
		{
			name:      "Update multi-cluster-management featuer from true to nil-should not be allowed",
			operation: admissionv1.Update,
			feature: apisv3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: "multi-cluster-management",
				},
				Spec: apisv3.FeatureSpec{
					Value: nil,
				},
				Status: apisv3.FeatureStatus{
					Dynamic:     true,
					Default:     false,
					LockedValue: nil,
				},
			},
			oldFeature: apisv3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: "multi-cluster-management",
				},
				Spec: apisv3.FeatureSpec{
					Value: pointer.Bool(true),
				},
				Status: apisv3.FeatureStatus{
					Dynamic:     true,
					Default:     false,
					LockedValue: nil,
				},
			},
			allowed: false,
			wantErr: false,
		},
		{
			name:      "Update multi-cluster-management featuer from true to nil with default is true-should be allowed",
			operation: admissionv1.Update,
			feature: apisv3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: "multi-cluster-management",
				},
				Spec: apisv3.FeatureSpec{
					Value: nil,
				},
				Status: apisv3.FeatureStatus{
					Dynamic:     true,
					Default:     true,
					LockedValue: nil,
				},
			},
			oldFeature: apisv3.Feature{
				ObjectMeta: metav1.ObjectMeta{
					Name: "multi-cluster-management",
				},
				Spec: apisv3.FeatureSpec{
					Value: pointer.Bool(true),
				},
				Status: apisv3.FeatureStatus{
					Dynamic:     true,
					Default:     true,
					LockedValue: nil,
				},
			},
			allowed: true,
			wantErr: false,
		},
	}

	validator := Validator{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := createFeatureRequest(t, &tt)
			resp, err := validator.Admit(request)
			assert.Equal(t, tt.wantErr, err != nil)
			if !tt.wantErr {
				assert.Equal(t, tt.allowed, resp.Allowed)
			}
		})
	}
}

func createFeatureRequest(t *testing.T, s *test) *admission.Request {
	t.Helper()
	gvk := metav1.GroupVersionKind{Version: "v3", Group: "management.cattle.io", Kind: "Feature"}
	gvr := metav1.GroupVersionResource{Version: "v3", Group: "management.cattle.io", Resource: "features"}

	req := &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:             "",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Name:            s.feature.Name,
			Operation:       s.operation,
			UserInfo:        authenticationv1.UserInfo{Username: "test", UID: ""},
			Object:          runtime.RawExtension{},
			Options:         runtime.RawExtension{},
		},
		Context: context.Background(),
	}
	if s.operation == admissionv1.Update {
		oldobj, err := json.Marshal(s.oldFeature)
		require.NoError(t, err, "Failed to marshal old Feature while creating request")
		req.OldObject = runtime.RawExtension{
			Raw: oldobj,
		}
	}
	var err error
	req.Object.Raw, err = json.Marshal(s.feature)
	require.NoError(t, err, "Failed to marshal Feature while creating request")
	return req
}
