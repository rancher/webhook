package clusterrole

import (
	"context"
	"encoding/json"
	"testing"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/require"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

var (
	gvk = metav1.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "Role"}
	gvr = metav1.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "roles"}
)

func TestAdmit(t *testing.T) {
	t.Parallel()

	defaultRole := &v1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}
	emptyRole := &v1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{},
		},
	}
	roleWithOwnerLabel := &v1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			Labels: map[string]string{
				grOwnerLabel: "gr-owner",
			},
		},
	}
	roleWithNewOwnerLabel := &v1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			Labels: map[string]string{
				grOwnerLabel: "new-owner",
			},
		},
	}

	type args struct {
		oldRole *v1.ClusterRole
		newRole *v1.ClusterRole
	}
	type test struct {
		name    string
		args    args
		allowed bool
	}
	tests := []test{
		{
			name: "updating with 2 nil labels maps allowed",
			args: args{
				oldRole: defaultRole.DeepCopy(),
				newRole: defaultRole.DeepCopy(),
			},
			allowed: true,
		},
		{
			name: "updating with 2 empty labels maps allowed",
			args: args{
				oldRole: emptyRole.DeepCopy(),
				newRole: emptyRole.DeepCopy(),
			},
			allowed: true,
		},
		{
			name: "updating labels other than grOwner allowed",
			args: args{
				oldRole: roleWithOwnerLabel.DeepCopy(),
				newRole: &v1.ClusterRole{
					ObjectMeta: metav1.ObjectMeta{
						Name: "default",
						Labels: map[string]string{
							"new-label":  "test-value",
							grOwnerLabel: "gr-owner",
						},
					},
				},
			},
			allowed: true,
		},
		{
			name: "adding gr-owner label allowed",
			args: args{
				oldRole: defaultRole.DeepCopy(),
				newRole: roleWithNewOwnerLabel.DeepCopy(),
			},
			allowed: true,
		},
		{
			name: "adding gr-owner label to empty labels map allowed",
			args: args{
				oldRole: emptyRole.DeepCopy(),
				newRole: roleWithNewOwnerLabel.DeepCopy(),
			},
			allowed: true,
		},
		{
			name: "modifying gr-owner label not allowed",
			args: args{
				oldRole: roleWithOwnerLabel.DeepCopy(),
				newRole: roleWithNewOwnerLabel.DeepCopy(),
			},
			allowed: false,
		},
		{
			name: "removing gr-owner label not allowed",
			args: args{
				oldRole: roleWithOwnerLabel.DeepCopy(),
				newRole: defaultRole.DeepCopy(),
			},
			allowed: false,
		},
		{
			name: "replacing labels with empty map not allowed",
			args: args{
				oldRole: roleWithOwnerLabel.DeepCopy(),
				newRole: emptyRole.DeepCopy(),
			},
			allowed: false,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			req := &admission.Request{
				AdmissionRequest: admissionv1.AdmissionRequest{
					UID:             "1",
					Kind:            gvk,
					Resource:        gvr,
					RequestKind:     &gvk,
					RequestResource: &gvr,
					Operation:       admissionv1.Update,
					Object:          runtime.RawExtension{},
					OldObject:       runtime.RawExtension{},
				},
				Context: context.Background(),
			}
			var err error
			req.Object.Raw, err = json.Marshal(test.args.newRole)
			require.NoError(t, err)
			req.OldObject.Raw, err = json.Marshal(test.args.oldRole)
			require.NoError(t, err)

			validator := NewValidator()
			admitter := validator.Admitters()
			response, err := admitter[0].Admit(req)
			require.NoError(t, err)
			require.Equalf(t, test.allowed, response.Allowed, "Response was incorrectly validated wanted response.Allowed = '%v' got '%v' message=%+v", test.allowed, response.Allowed, response.Result)
		})
	}
}

func TestAdmin_errors(t *testing.T) {
	t.Parallel()

	req := &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Operation:       admissionv1.Update,
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
		Context: context.Background(),
	}
	req.Object = runtime.RawExtension{}

	validator := NewValidator()
	admitter := validator.Admitters()
	_, err := admitter[0].Admit(req)
	require.Error(t, err, "Admit should fail on bad request object")
}
