package globalrole

import (
	"encoding/json"
	"testing"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authenicationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

var (
	globalRoleGVR = metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "globalRoles"}
	globalRoleGVK = metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "GlobalRole"}
)

func TestAdmitInvalidOrDeletedGlobalRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		globalRole v3.GlobalRole
		wantError  bool
		wantAdmit  bool
	}{
		{
			name: "global role in the process of being deleted is admitted",
			globalRole: v3.GlobalRole{
				ObjectMeta: metav1.ObjectMeta{
					DeletionTimestamp: admission.Ptr(metav1.NewTime(time.Now())),
				},
			},
			wantAdmit: true,
		},
		{
			name: "a policy rule lacks a verb",
			globalRole: v3.GlobalRole{
				Rules: []v1.PolicyRule{
					{
						Verbs: []string{"list"},
					},
					{
						Verbs: nil,
					},
				},
			},
			wantAdmit: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			// The resolver should not run in these tests. Making it not nil to get test errors instead of panics.
			resolver, _ := validation.NewTestRuleResolver(nil, nil, nil, nil)
			admitters := NewValidator(resolver).Admitters()
			assert.Len(t, admitters, 1)

			req := admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation:       admissionv1.Create,
					UID:             "2",
					Kind:            globalRoleGVK,
					Resource:        globalRoleGVR,
					RequestKind:     &globalRoleGVK,
					RequestResource: &globalRoleGVR,
					Name:            "my-global-role",
					UserInfo:        authenicationv1.UserInfo{Username: "test-user", UID: ""},
					Object:          runtime.RawExtension{},
					OldObject:       runtime.RawExtension{},
				},
			}
			var err error
			req.Object.Raw, err = json.Marshal(test.globalRole)
			require.NoError(t, err, "Failed to marshal new GlobalRole while creating request")

			response, err := admitters[0].Admit(&req)
			if test.wantError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, test.wantAdmit, response.Allowed)
			}
		})
	}
}

func TestRejectsBadRequest(t *testing.T) {
	t.Parallel()
	// The resolver should not run in these tests. Making it not nil to get test errors instead of panics.
	resolver, _ := validation.NewTestRuleResolver(nil, nil, nil, nil)
	admitters := NewValidator(resolver).Admitters()
	assert.Len(t, admitters, 1)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation:       admissionv1.Create,
			UID:             "2",
			Kind:            globalRoleGVK,
			Resource:        globalRoleGVR,
			RequestKind:     &globalRoleGVK,
			RequestResource: &globalRoleGVR,
			Name:            "my-global-role",
			UserInfo:        authenicationv1.UserInfo{Username: "test-user", UID: ""},
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
	}

	_, err := admitters[0].Admit(&req)
	require.Error(t, err)
}

func TestAdmitValidGlobalRole(t *testing.T) {
	t.Parallel()
	// The resolver should not run in these tests. Making it not nil to get test errors instead of panics.
	resolver, _ := validation.NewTestRuleResolver(nil, nil, nil, nil)

	admitters := NewValidator(resolver).Admitters()
	assert.Len(t, admitters, 1)

	req := admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
		},
	}
	var err error
	req.Object.Raw, err = json.Marshal(v3.GlobalRole{})
	require.NoError(t, err, "Failed to marshal new GlobalRole while creating request")

	response, err := admitters[0].Admit(&req)
	require.NoError(t, err)
	assert.True(t, response.Allowed)
}
