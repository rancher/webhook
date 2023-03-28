package namespace_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/resources/common"
	"github.com/rancher/webhook/pkg/resources/core/v1/namespace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authrizationv1 "k8s.io/api/authorization/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8fake "k8s.io/client-go/kubernetes/typed/authorization/v1/fake"
	k8testing "k8s.io/client-go/testing"
)

const failSarUser = "nonadminuser"
const allowSarUser = "adminuser"
const sarErrorUser = "sarerroruser"

type test struct {
	name         string
	userName     string
	clusterName  string
	operation    admissionv1.Operation
	namespace    v1.Namespace
	oldNamespace v1.Namespace
	allowed      bool
	wantErr      bool
}

func TestValidator_Admit(t *testing.T) {

	tests := []test{
		{
			name:        "Update namespace PSA for admin user-should be allowed",
			userName:    allowSarUser,
			clusterName: "validcluster",
			operation:   admissionv1.Update,
			namespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "anynamespace",
					Labels: map[string]string{
						common.EnforceLabel: "baseline",
					},
				},
			},
			oldNamespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "anynamespace",
					Labels: map[string]string{},
				},
			},
			wantErr: false,
			allowed: true,
		},
		{
			name:        "Update NON PSA for NON admin user-should be allowed",
			userName:    failSarUser,
			clusterName: "validcluster",
			operation:   admissionv1.Update,
			namespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "anynamespace",
					Labels: map[string]string{
						"someotherlabelkey": "somevalue",
						common.EnforceLabel: "baseline",
					},
				},
			},
			oldNamespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "anynamespace",
					Labels: map[string]string{
						common.EnforceLabel: "baseline",
					},
				},
			},
			wantErr: false,
			allowed: true,
		},
		{
			name:        "Update PSA for NON admin user-should not be allowed",
			userName:    failSarUser,
			clusterName: "validcluster",
			operation:   admissionv1.Update,
			namespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "anynamespace",
					Labels: map[string]string{
						common.EnforceLabel: "baseline",
					},
				},
			},
			oldNamespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "anynamespace",
					Labels: map[string]string{},
				},
			},
			wantErr: false,
			allowed: false,
		},
		{
			name:        "Delete update PSA for NON admin user-should not be allowed",
			userName:    failSarUser,
			clusterName: "validcluster",
			operation:   admissionv1.Update,
			namespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "anynamespace",
					Labels: map[string]string{},
				},
			},
			oldNamespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "anynamespace",
					Labels: map[string]string{
						common.EnforceLabel: "baseline",
					},
				},
			},
			wantErr: false,
			allowed: false,
		},
		{
			name:        "Delete update PSA for admin user should be allowed",
			userName:    allowSarUser,
			clusterName: "validcluster",
			operation:   admissionv1.Update,
			namespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "anynamespace",
					Labels: map[string]string{},
				},
			},
			oldNamespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "anynamespace",
					Labels: map[string]string{
						common.EnforceLabel: "baseline",
					},
				},
			},
			wantErr: false,
			allowed: true,
		},
		{
			name:        "Update multiple PSA for allowed user",
			userName:    allowSarUser,
			clusterName: "validcluster",
			operation:   admissionv1.Update,
			namespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "anynamespace",
					Labels: map[string]string{
						common.EnforceLabel: "baseline",
						common.WarnLabel:    "baseline",
						common.AuditLabel:   "baseline",
					},
				},
			},
			oldNamespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "anynamespace",
					Labels: map[string]string{},
				},
			},
			wantErr: false,
			allowed: true,
		},
		{
			name:        "Update multiple PSA and non PSA for allowed user",
			userName:    allowSarUser,
			clusterName: "validcluster",
			operation:   admissionv1.Update,
			namespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "anynamespace",
					Labels: map[string]string{
						common.EnforceLabel:        "baseline",
						common.WarnLabel:           "baseline",
						common.AuditLabel:          "baseline",
						common.AuditVersionLabel:   "restricted",
						common.WarnVersionLabel:    "restricted",
						common.EnforceVersionLabel: "restricted",
						"randomkey":                "randomvalue",
					},
					Annotations: map[string]string{
						"annotationkey": "annotationlabel",
					},
				},
			},
			oldNamespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "anynamespace",
					Labels: map[string]string{},
				},
			},
			wantErr: false,
			allowed: true,
		},
		{
			name:        "Update multiple PSA and non PSA for non allowed user",
			userName:    failSarUser,
			clusterName: "validcluster",
			operation:   admissionv1.Update,
			namespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "anynamespace",
					Labels: map[string]string{
						common.EnforceLabel: "baseline",
						common.WarnLabel:    "baseline",
						common.AuditLabel:   "baseline",
						"randomkey":         "randomvalue",
					},
					Annotations: map[string]string{
						"annotationkey": "annotationlabel",
					},
				},
			},
			oldNamespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "anynamespace",
					Labels: map[string]string{},
				},
			},
			wantErr: false,
			allowed: false,
		},
		{
			name:        "Update things unrelated to PSA labels",
			userName:    allowSarUser,
			clusterName: "validcluster",
			operation:   admissionv1.Update,
			namespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "anynamespace",
					Labels: map[string]string{
						"randomkey": "randomvalue",
					},
					Annotations: map[string]string{
						"annotationkey": "annotationlabel",
					},
					GenerateName: "abcde",
				},
			},
			oldNamespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "anynamespace",
					Labels: map[string]string{},
				},
			},
			wantErr: false,
			allowed: true,
		},
		{
			name:        "SAR create failed for update attempt",
			userName:    sarErrorUser,
			clusterName: "validcluster",
			operation:   admissionv1.Update,
			namespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "anynamespace",
					Labels: map[string]string{
						common.EnforceLabel: "baseline",
					},
					GenerateName: "abcde",
				},
			},
			oldNamespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name:   "anynamespace",
					Labels: map[string]string{},
				},
			},
			wantErr: true,
			allowed: true,
		},
		{
			name:        "Create namespace with PSA for admin user-should be allowed",
			userName:    allowSarUser,
			clusterName: "validcluster",
			operation:   admissionv1.Create,
			namespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "anynamespace",
					Labels: map[string]string{
						common.EnforceLabel: "baseline",
					},
				},
			},
			wantErr: false,
			allowed: true,
		},
		{
			name:        "Create namespace with PSA for not-permitted user should not be allowed",
			userName:    failSarUser,
			clusterName: "validcluster",
			operation:   admissionv1.Create,
			namespace: v1.Namespace{
				ObjectMeta: metav1.ObjectMeta{
					Name: "anynamespace",
					Labels: map[string]string{
						common.EnforceLabel: "baseline",
					},
				},
			},
			wantErr: false,
			allowed: false,
		},
	}

	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}
	validator := namespace.NewValidator(fakeSAR)

	k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
		createAction := action.(k8testing.CreateActionImpl)
		review := createAction.GetObject().(*authrizationv1.SubjectAccessReview)
		spec := review.Spec

		// simulate SAR not allowed
		if spec.User == failSarUser {
			review.Status.Allowed = false
			review.Status.Reason = fmt.Sprintf("%s %s", "Can not update project PSA for:", spec.User)
			return true, review, nil
		} else if spec.User == sarErrorUser {
			return true, nil, fmt.Errorf("SAR creation failed for user #{spec.User}")
		}
		review.Status.Allowed = true
		return true, review, nil
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := createNamespaceRequest(t, &tt)
			admitters := validator.Admitters()
			assert.Len(t, admitters, 1)
			resp, err := admitters[0].Admit(request)
			assert.Equal(t, tt.wantErr, err != nil)
			if !tt.wantErr {
				assert.Equal(t, tt.allowed, resp.Allowed)
			}
		})
	}
}

func createNamespaceRequest(t *testing.T, s *test) *admission.Request {
	t.Helper()
	gvk := metav1.GroupVersionKind{Version: "v1", Kind: "Namespace"}
	gvr := metav1.GroupVersionResource{Version: "v1", Resource: "namespace"}

	req := &admission.Request{
		AdmissionRequest: admissionv1.AdmissionRequest{
			UID:             "",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Name:            s.namespace.Name,
			Operation:       s.operation,
			UserInfo:        authenticationv1.UserInfo{Username: s.userName, UID: ""},
			Object:          runtime.RawExtension{},
			Options:         runtime.RawExtension{},
		},
		Context: context.Background(),
	}
	if s.operation == admissionv1.Update {
		oldobj, err := json.Marshal(s.oldNamespace)
		require.NoError(t, err, "Failed to marshal old Namespace while creating request")
		req.OldObject = runtime.RawExtension{
			Raw: oldobj,
		}
	}
	var err error
	req.Object.Raw, err = json.Marshal(s.namespace)
	require.NoError(t, err, "Failed to marshal Namespace while creating request")
	return req
}
