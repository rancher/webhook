package clusterrolebinding

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

var (
	gvk = metav1.GroupVersionKind{Group: "rbac.authorization.k8s.io", Version: "v1", Kind: "RoleBinding"}
	gvr = metav1.GroupVersionResource{Group: "rbac.authorization.k8s.io", Version: "v1", Resource: "rolebindings"}
)

func TestAdmit(t *testing.T) {
	t.Parallel()

	defaultRoleBinding := &v1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}
	emptyLabelsRoleBinding := &v1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Labels: map[string]string{},
			Name:   "default",
		},
	}
	roleBindingWithOwnerLabel := &v1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			Labels: map[string]string{
				grbOwnerLabel: "grb-owner",
			},
		},
	}
	roleBindingWithNewOwnerLabel := &v1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
			Labels: map[string]string{
				grbOwnerLabel: "new-owner",
			},
		},
	}

	type args struct {
		oldRB *v1.ClusterRoleBinding
		newRB *v1.ClusterRoleBinding
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
				oldRB: defaultRoleBinding.DeepCopy(),
				newRB: defaultRoleBinding.DeepCopy(),
			},
			allowed: true,
		},
		{
			name: "updating with 2 empty labels maps allowed",
			args: args{
				oldRB: emptyLabelsRoleBinding.DeepCopy(),
				newRB: emptyLabelsRoleBinding.DeepCopy(),
			},
			allowed: true,
		},
		{
			name: "updating labels other than grbOwner allowed",
			args: args{
				oldRB: roleBindingWithOwnerLabel.DeepCopy(),
				newRB: &v1.ClusterRoleBinding{
					ObjectMeta: metav1.ObjectMeta{
						Name: "default",
						Labels: map[string]string{
							"new-label":   "test-value",
							grbOwnerLabel: "grb-owner",
						},
					},
				},
			},
			allowed: true,
		},
		{
			name: "adding grb-owner label allowed",
			args: args{
				oldRB: defaultRoleBinding.DeepCopy(),
				newRB: roleBindingWithOwnerLabel.DeepCopy(),
			},
			allowed: true,
		},
		{
			name: "adding grb-owner label to empty labels map allowed",
			args: args{
				oldRB: emptyLabelsRoleBinding.DeepCopy(),
				newRB: roleBindingWithOwnerLabel.DeepCopy(),
			},
			allowed: true,
		},
		{
			name: "modifying grb-owner label not allowed",
			args: args{
				oldRB: roleBindingWithOwnerLabel.DeepCopy(),
				newRB: roleBindingWithNewOwnerLabel.DeepCopy(),
			},
			allowed: false,
		},
		{
			name: "removing grb-owner label not allowed",
			args: args{
				oldRB: roleBindingWithOwnerLabel.DeepCopy(),
				newRB: defaultRoleBinding.DeepCopy(),
			},
			allowed: false,
		},
		{
			name: "replacing labels with empty map not allowed",
			args: args{
				oldRB: roleBindingWithOwnerLabel.DeepCopy(),
				newRB: emptyLabelsRoleBinding.DeepCopy(),
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
			req.Object.Raw, err = json.Marshal(test.args.newRB)
			require.NoError(t, err)
			req.OldObject.Raw, err = json.Marshal(test.args.oldRB)
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
