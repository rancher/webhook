package projectpodsecuritytemplatebinding_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authrizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8fake "k8s.io/client-go/kubernetes/typed/authorization/v1/fake"
	k8testing "k8s.io/client-go/testing"

	"github.com/pkg/errors"
	apisv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resources/validation/projectpodsecuritytemplatebinding"
	"github.com/rancher/wrangler/pkg/webhook"
	"github.com/stretchr/testify/assert"
)

const ownedProject = "ownedproject"
const notOwnedProject = "notownedproject"
const allowedUser = "testUser"
const notAllowedUser = "noaccess"
const dummyCluster = "c-clust"
const invalidProject = "invalidproject"
const failSarCreateForUser = "usernosar"
const sarFailMessage = "cannot create sar for user"

func TestPPTRBUpdate(t *testing.T) {
	tests := []struct {
		name           string
		user           string
		project        string
		expectAdmitted bool
		expectErr      bool
		operation      v1.Operation
		psptpb         apisv3.PodSecurityPolicyTemplateProjectBinding
	}{
		{
			name:           "non owner user, should not have access",
			user:           notAllowedUser,
			project:        notOwnedProject,
			expectAdmitted: false,
			expectErr:      false,
			operation:      v1.Update,
			psptpb: apisv3.PodSecurityPolicyTemplateProjectBinding{
				TargetProjectName:             dummyCluster + ":" + notOwnedProject,
				PodSecurityPolicyTemplateName: "unrestricted",
			},
		},
		{
			name:           "update, project owner user, should have access",
			user:           allowedUser,
			project:        ownedProject,
			expectAdmitted: true,
			expectErr:      false,
			operation:      v1.Update,
			psptpb: apisv3.PodSecurityPolicyTemplateProjectBinding{
				TargetProjectName:             dummyCluster + ":" + ownedProject,
				PodSecurityPolicyTemplateName: "unrestricted",
			},
		},
		{
			name:           "create, project owner user, should have access",
			user:           allowedUser,
			project:        ownedProject,
			expectAdmitted: true,
			expectErr:      false,
			operation:      v1.Create,
			psptpb: apisv3.PodSecurityPolicyTemplateProjectBinding{
				TargetProjectName:             dummyCluster + ":" + ownedProject,
				PodSecurityPolicyTemplateName: "unrestricted",
			},
		},
		{
			name:           "invalid project given in request, should not have access",
			user:           allowedUser,
			project:        invalidProject,
			expectAdmitted: false,
			expectErr:      true,
			operation:      v1.Update,
			psptpb: apisv3.PodSecurityPolicyTemplateProjectBinding{
				TargetProjectName:             invalidProject,
				PodSecurityPolicyTemplateName: "unrestricted",
			},
		},
		{
			name:           "empty psptpb in request, expect error",
			user:           allowedUser,
			project:        invalidProject,
			expectAdmitted: false,
			expectErr:      true,
			operation:      v1.Update,
			psptpb:         apisv3.PodSecurityPolicyTemplateProjectBinding{},
		},
		{
			name:           "user can not create SAR, expect error",
			user:           failSarCreateForUser,
			project:        ownedProject,
			expectAdmitted: false,
			expectErr:      true,
			operation:      v1.Create,
			psptpb: apisv3.PodSecurityPolicyTemplateProjectBinding{
				TargetProjectName:             dummyCluster + ":" + ownedProject,
				PodSecurityPolicyTemplateName: "unrestricted",
			},
		},
	}

	k8Fake := &k8testing.Fake{}
	fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}
	validator := projectpodsecuritytemplatebinding.NewValidator(fakeSAR)

	k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
		createAction := action.(k8testing.CreateActionImpl)
		review := createAction.GetObject().(*authrizationv1.SubjectAccessReview)
		spec := review.Spec

		// simulate SAR create failure
		if spec.User == failSarCreateForUser {
			return true, review, errors.Errorf("%s %s", sarFailMessage, spec.User)
		}

		// If we have an allowed user and owned project, we should allow the action
		review.Status.Allowed = spec.User == allowedUser &&
			spec.ResourceAttributes.Namespace == ownedProject
		return true, review, nil
	})

	for _, testCase := range tests {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			response, request := createPSPTPBRequestAndResponse(t, testCase.user, testCase.operation, testCase.psptpb)
			err := validator.Admit(response, request)

			assert.Equal(t, testCase.expectAdmitted, response.Allowed)
			if testCase.expectErr {
				assert.Error(t, err)
			}
			if testCase.user == failSarCreateForUser {
				assert.ErrorContains(t, err, "cannot create sar for user")
			}
			if !testCase.expectErr && !testCase.expectAdmitted {
				assert.True(t, response.Result.Code == http.StatusForbidden)
			}
		})
	}
}

func createPSPTPBRequestAndResponse(t *testing.T, username string, operation v1.Operation, psptpb apisv3.PodSecurityPolicyTemplateProjectBinding) (*webhook.Response, *webhook.Request) {
	t.Helper()
	gvk := metav1.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "ProjectPodSecurityTemplateBinding"}
	gvr := metav1.GroupVersionResource{Group: "management.cattle.io", Version: "v3", Resource: "projectpodsecuritytemplatebinding"}
	req := &webhook.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:             "1",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Name:            psptpb.Name,
			Namespace:       psptpb.Namespace,
			Operation:       operation,
			UserInfo:        authenticationv1.UserInfo{Username: username, UID: ""},
			Object:          runtime.RawExtension{},
			OldObject:       runtime.RawExtension{},
		},
		Context:     context.Background(),
		ObjTemplate: &apisv3.PodSecurityPolicyTemplateProjectBinding{},
	}
	var err error
	req.Object.Raw, err = json.Marshal(psptpb)
	assert.NoError(t, err, "Failed to marshal PSPTPB while creating request")
	resp := &webhook.Response{
		AdmissionResponse: v1.AdmissionResponse{
			UID:     req.UID,
			Allowed: false,
			Result:  &metav1.Status{},
		},
	}
	return resp, req
}
