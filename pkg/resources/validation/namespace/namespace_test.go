package namespace

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/rancher/wrangler/pkg/webhook"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8fake "k8s.io/client-go/kubernetes/typed/authorization/v1/fake"
	k8testing "k8s.io/client-go/testing"
)

func TestValidateProjectNamespaceAnnotations(t *testing.T) {
	tests := []struct {
		name                      string
		operationType             v1.Operation
		projectAnnotationValue    string
		oldProjectAnnotationValue string
		includeProjectAnnotation  bool
		targetProject             string
		userCanAccessProject      bool
		sarError                  bool
		wantError                 bool
		wantAllowed               bool
	}{
		{
			name:                     "user can access, create",
			operationType:            v1.Create,
			projectAnnotationValue:   "c-123xyz:p-123xyz",
			includeProjectAnnotation: true,
			targetProject:            "p-123xyz",
			userCanAccessProject:     true,
			sarError:                 false,
			wantError:                false,
			wantAllowed:              true,
		},
		{
			name:                      "user can access, update",
			operationType:             v1.Update,
			projectAnnotationValue:    "c-123xyz:p-123xyz",
			oldProjectAnnotationValue: "c-123abc:p-123abc",
			includeProjectAnnotation:  true,
			targetProject:             "p-123xyz",
			userCanAccessProject:      true,
			sarError:                  false,
			wantError:                 false,
			wantAllowed:               true,
		},
		{
			name:                      "user isn't modifying projectID, update",
			operationType:             v1.Update,
			projectAnnotationValue:    "c-123xyz:p-123xyz",
			oldProjectAnnotationValue: "c-123xyz:p-123xyz",
			includeProjectAnnotation:  true,
			targetProject:             "p-123xyz",
			userCanAccessProject:      false,
			wantError:                 false,
			wantAllowed:               true,
		},
		{
			name:                     "user can't access, create",
			operationType:            v1.Create,
			projectAnnotationValue:   "c-123xyz:p-123xyz",
			includeProjectAnnotation: true,
			targetProject:            "p-123xyz",
			userCanAccessProject:     false,
			sarError:                 false,
			wantError:                false,
			wantAllowed:              false,
		},
		{
			name:                      "user can't access, update",
			operationType:             v1.Update,
			projectAnnotationValue:    "c-123xyz:p-123xyz",
			oldProjectAnnotationValue: "c-123abc:p-123abc",
			includeProjectAnnotation:  true,
			targetProject:             "p-123xyz",
			userCanAccessProject:      false,
			sarError:                  false,
			wantError:                 false,
			wantAllowed:               false,
		},
		{
			name:                     "no annotation, create",
			operationType:            v1.Create,
			includeProjectAnnotation: false,
			targetProject:            "p-123xyz",
			userCanAccessProject:     false,
			sarError:                 false,
			wantError:                false,
			wantAllowed:              true,
		},
		{
			name:                     "no annotation, update",
			operationType:            v1.Update,
			includeProjectAnnotation: false,
			targetProject:            "p-123xyz",
			userCanAccessProject:     false,
			sarError:                 false,
			wantError:                false,
			wantAllowed:              true,
		},
		{
			name:                     "invalid annotation, create",
			operationType:            v1.Create,
			projectAnnotationValue:   "not-valid-project",
			includeProjectAnnotation: true,
			targetProject:            "p-123xyz",
			userCanAccessProject:     false,
			sarError:                 false,
			wantError:                true,
			wantAllowed:              false,
		},
		{
			name:                      "invalid annotation, update",
			operationType:             v1.Update,
			projectAnnotationValue:    "not-valid-project",
			oldProjectAnnotationValue: "c-123abc:p-123abc",
			includeProjectAnnotation:  true,
			targetProject:             "p-123xyz",
			userCanAccessProject:      false,
			sarError:                  false,
			wantError:                 true,
			wantAllowed:               false,
		},
		{
			name:                     "empty annotation, create",
			operationType:            v1.Create,
			projectAnnotationValue:   "",
			includeProjectAnnotation: true,
			targetProject:            "p-123xyz",
			userCanAccessProject:     false,
			sarError:                 false,
			wantError:                true,
			wantAllowed:              false,
		},
		{
			name:                      "empty annotation, update",
			operationType:             v1.Update,
			projectAnnotationValue:    "",
			oldProjectAnnotationValue: "c-123abc:p-123abc",
			includeProjectAnnotation:  true,
			targetProject:             "p-123xyz",
			userCanAccessProject:      false,
			sarError:                  false,
			wantError:                 true,
			wantAllowed:               false,
		},
		{
			name:                      "empty old annotation, update",
			operationType:             v1.Update,
			projectAnnotationValue:    "c-123xyz:p-123xyz",
			oldProjectAnnotationValue: "",
			includeProjectAnnotation:  true,
			targetProject:             "p-123xyz",
			userCanAccessProject:      false,
			sarError:                  false,
			wantError:                 false,
			wantAllowed:               false,
		},
		{
			name:                     "sar error, create",
			operationType:            v1.Create,
			projectAnnotationValue:   "c-123xyz:p-123xyz",
			includeProjectAnnotation: true,
			targetProject:            "p-123xyz",
			userCanAccessProject:     false,
			sarError:                 true,
			wantError:                true,
			wantAllowed:              false,
		},
		{
			name:                      "sar error, update",
			operationType:             v1.Update,
			projectAnnotationValue:    "c-123xyz:p-123xyz",
			oldProjectAnnotationValue: "c-123abc:p-123abc",
			includeProjectAnnotation:  true,
			targetProject:             "p-123xyz",
			userCanAccessProject:      false,
			sarError:                  true,
			wantError:                 true,
			wantAllowed:               false,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			k8Fake := &k8testing.Fake{}
			fakeSAR := &k8fake.FakeSubjectAccessReviews{Fake: &k8fake.FakeAuthorizationV1{Fake: k8Fake}}
			validator := Validator{
				sar: fakeSAR,
			}
			k8Fake.AddReactor("create", "subjectaccessreviews", func(action k8testing.Action) (handled bool, ret runtime.Object, err error) {
				createAction := action.(k8testing.CreateActionImpl)
				review := createAction.GetObject().(*authorizationv1.SubjectAccessReview)
				spec := review.Spec
				if sarIsForProjectGVR(spec) && spec.ResourceAttributes.Verb == manageNSVerb && spec.ResourceAttributes.Name == test.targetProject {
					if test.sarError {
						return true, nil, fmt.Errorf("error when creating sar, server unavailable")
					}
					review.Status.Allowed = test.userCanAccessProject
					return true, review, nil
				}
				// if this wasn't for our project, don't handle the response
				return false, nil, nil
			})
			request, err := createAnnotationNamespaceRequest(test.projectAnnotationValue, test.oldProjectAnnotationValue, test.includeProjectAnnotation, test.operationType)
			assert.NoError(t, err)
			response := webhook.Response{}
			err = validator.Admit(&response, request)
			if test.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, test.wantAllowed, response.Allowed)
			}
		})
	}
}

func sarIsForProjectGVR(sarSpec authorizationv1.SubjectAccessReviewSpec) bool {
	return sarSpec.ResourceAttributes.Group == projectsGVR.Group &&
		sarSpec.ResourceAttributes.Version == projectsGVR.Version &&
		sarSpec.ResourceAttributes.Resource == projectsGVR.Resource
}

func createAnnotationNamespaceRequest(newProjectAnnotation, oldProjectAnnotation string, includeProjectAnnotation bool, operation v1.Operation) (*webhook.Request, error) {
	gvk := metav1.GroupVersionKind{Version: "v1", Kind: "Namespace"}
	gvr := metav1.GroupVersionResource{Version: "v1", Resource: "namespace"}
	ns := corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-ns",
		},
	}
	if includeProjectAnnotation {
		ns.Annotations = map[string]string{
			projectNSAnnotation: newProjectAnnotation,
		}
	}

	req := &webhook.Request{
		AdmissionRequest: v1.AdmissionRequest{
			UID:             "",
			Kind:            gvk,
			Resource:        gvr,
			RequestKind:     &gvk,
			RequestResource: &gvr,
			Name:            ns.Name,
			Operation:       operation,
			UserInfo:        authenticationv1.UserInfo{Username: "test-user", UID: ""},
			Object:          runtime.RawExtension{},
			Options:         runtime.RawExtension{},
		},
		Context:     context.Background(),
		ObjTemplate: &corev1.Namespace{},
	}

	var err error
	req.Object.Raw, err = json.Marshal(ns)
	if err != nil {
		return nil, err
	}
	if operation == v1.Update {
		if includeProjectAnnotation {
			ns.Annotations[projectNSAnnotation] = oldProjectAnnotation
		}
		obj, err := json.Marshal(ns)
		if err != nil {
			return nil, err
		}
		req.OldObject = runtime.RawExtension{
			Raw: obj,
		}
	}
	return req, nil
}
