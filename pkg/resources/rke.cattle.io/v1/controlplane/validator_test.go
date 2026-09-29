package controlplane

import (
	"context"
	"encoding/json"
	"testing"

	rkev1 "github.com/rancher/rancher/pkg/apis/rke.cattle.io/v1"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func TestValidator_Metadata(t *testing.T) {
	t.Parallel()

	validator := NewValidator()
	assert.Equal(t, schema.GroupVersionResource{
		Group:    "rke.cattle.io",
		Version:  "v1",
		Resource: "rkecontrolplanes",
	}, validator.GVR())

	assert.Equal(t, []admissionregistrationv1.OperationType{
		admissionregistrationv1.Create,
		admissionregistrationv1.Update,
	}, validator.Operations())

	webhooks := validator.ValidatingWebhook(admissionregistrationv1.WebhookClientConfig{})
	require.Len(t, webhooks, 1)
	assert.Equal(t, admissionregistrationv1.NamespacedScope, *webhooks[0].Rules[0].Scope)

	admitters := validator.Admitters()
	assert.Len(t, admitters, 1)
}

func TestValidator_Admit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		cp          *rkev1.RKEControlPlane
		operation   admissionv1.Operation
		wantAllowed bool
	}{
		{
			name: "create with empty data directories",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{},
			},
			operation:   admissionv1.Create,
			wantAllowed: true,
		},
		{
			name: "create with valid data directories",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{
					ClusterConfiguration: rkev1.ClusterConfiguration{
						DataDirectories: rkev1.DataDirectories{
							K8sDistro:    "/var/lib/rancher/rke2",
							Provisioning: "/var/lib/rancher/provisioning",
							SystemAgent:  "/opt/rancher/system-agent",
						},
					},
				},
			},
			operation:   admissionv1.Create,
			wantAllowed: true,
		},
		{
			name: "create with relative path in K8sDistro",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{
					ClusterConfiguration: rkev1.ClusterConfiguration{
						DataDirectories: rkev1.DataDirectories{
							K8sDistro: "relative/path",
						},
					},
				},
			},
			operation:   admissionv1.Create,
			wantAllowed: false,
		},
		{
			name: "create with dirty path in Provisioning",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{
					ClusterConfiguration: rkev1.ClusterConfiguration{
						DataDirectories: rkev1.DataDirectories{
							Provisioning: "/var/lib/../var/lib",
						},
					},
				},
			},
			operation:   admissionv1.Create,
			wantAllowed: false,
		},
		{
			name: "create with trailing slash in SystemAgent",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{
					ClusterConfiguration: rkev1.ClusterConfiguration{
						DataDirectories: rkev1.DataDirectories{
							SystemAgent: "/opt/system-agent/",
						},
					},
				},
			},
			operation:   admissionv1.Create,
			wantAllowed: false,
		},
		{
			name: "create with shell expression in SystemAgent",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{
					ClusterConfiguration: rkev1.ClusterConfiguration{
						DataDirectories: rkev1.DataDirectories{
							SystemAgent: "/opt/$(malicious)",
						},
					},
				},
			},
			operation:   admissionv1.Create,
			wantAllowed: false,
		},
		{
			name: "create with equal data directories",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{
					ClusterConfiguration: rkev1.ClusterConfiguration{
						DataDirectories: rkev1.DataDirectories{
							K8sDistro:    "/var/lib/rancher",
							Provisioning: "/var/lib/rancher",
						},
					},
				},
			},
			operation:   admissionv1.Create,
			wantAllowed: false,
		},
		{
			name: "create with nested data directories",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{
					ClusterConfiguration: rkev1.ClusterConfiguration{
						DataDirectories: rkev1.DataDirectories{
							Provisioning: "/var/lib/rancher",
							SystemAgent:  "/var/lib/rancher/agent",
						},
					},
				},
			},
			operation:   admissionv1.Create,
			wantAllowed: false,
		},
		{
			name: "update with empty data directories",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{},
			},
			operation:   admissionv1.Update,
			wantAllowed: true,
		},
		{
			name: "update with valid data directories",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{
					ClusterConfiguration: rkev1.ClusterConfiguration{
						DataDirectories: rkev1.DataDirectories{
							K8sDistro:    "/var/lib/rancher/rke2",
							Provisioning: "/var/lib/rancher/provisioning",
							SystemAgent:  "/opt/rancher/system-agent",
						},
					},
				},
			},
			operation:   admissionv1.Update,
			wantAllowed: true,
		},
		{
			name: "update with relative path in K8sDistro",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{
					ClusterConfiguration: rkev1.ClusterConfiguration{
						DataDirectories: rkev1.DataDirectories{
							K8sDistro: "relative/path",
						},
					},
				},
			},
			operation:   admissionv1.Update,
			wantAllowed: false,
		},
		{
			name: "update with dirty path in Provisioning",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{
					ClusterConfiguration: rkev1.ClusterConfiguration{
						DataDirectories: rkev1.DataDirectories{
							Provisioning: "/var/lib/../var/lib",
						},
					},
				},
			},
			operation:   admissionv1.Update,
			wantAllowed: false,
		},
		{
			name: "update with shell expression in SystemAgent",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{
					ClusterConfiguration: rkev1.ClusterConfiguration{
						DataDirectories: rkev1.DataDirectories{
							SystemAgent: "/opt/system-agent;rm",
						},
					},
				},
			},
			operation:   admissionv1.Update,
			wantAllowed: false,
		},
		{
			name: "update with equal data directories",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{
					ClusterConfiguration: rkev1.ClusterConfiguration{
						DataDirectories: rkev1.DataDirectories{
							K8sDistro:    "/var/lib/rancher",
							Provisioning: "/var/lib/rancher",
						},
					},
				},
			},
			operation:   admissionv1.Update,
			wantAllowed: false,
		},
		{
			name: "update with nested data directories",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{
					ClusterConfiguration: rkev1.ClusterConfiguration{
						DataDirectories: rkev1.DataDirectories{
							Provisioning: "/var/lib/rancher",
							SystemAgent:  "/var/lib/rancher/agent",
						},
					},
				},
			},
			operation:   admissionv1.Update,
			wantAllowed: false,
		},
		{
			name: "delete operation is allowed",
			cp: &rkev1.RKEControlPlane{
				Spec: rkev1.RKEControlPlaneSpec{
					ClusterConfiguration: rkev1.ClusterConfiguration{
						DataDirectories: rkev1.DataDirectories{
							K8sDistro: "relative/path",
						},
					},
				},
			},
			operation:   admissionv1.Delete,
			wantAllowed: true,
		},
	}

	validator := NewValidator()
	admitters := validator.Admitters()
	require.Len(t, admitters, 1)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req, err := createRKEControlPlaneRequest(tt.cp, tt.operation)
			require.NoError(t, err)

			response, err := admitters[0].Admit(req)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAllowed, response.Allowed)
		})
	}
}

func TestValidator_Admit_UnmarshalError(t *testing.T) {
	t.Parallel()

	validator := NewValidator()
	admitter := validator.Admitters()[0]

	req := &admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Operation: admissionv1.Create,
			Object: runtime.RawExtension{
				Raw: []byte(`{invalid-json`),
			},
		},
	}

	response, err := admitter.Admit(req)
	assert.Error(t, err)
	assert.Nil(t, response)
}

func createRKEControlPlaneRequest(cp *rkev1.RKEControlPlane, op admissionv1.Operation) (*admission.Request, error) {
	req := &admission.Request{
		Context: context.Background(),
		AdmissionRequest: admissionv1.AdmissionRequest{
			Kind: metav1.GroupVersionKind{
				Group:   "rke.cattle.io",
				Version: "v1",
				Kind:    "RKEControlPlane",
			},
			Resource: metav1.GroupVersionResource{
				Group:    "rke.cattle.io",
				Version:  "v1",
				Resource: "rkecontrolplanes",
			},
			Operation: op,
		},
	}

	if cp != nil {
		raw, err := json.Marshal(cp)
		if err != nil {
			return nil, err
		}
		if op == admissionv1.Delete {
			req.OldObject.Raw = raw
		} else {
			req.Object.Raw = raw
		}
	}

	return req, nil
}
