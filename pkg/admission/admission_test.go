package admission_test

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/assert"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/admissionregistration/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

type handlerResponse struct {
	hasAllow bool
	hasError bool
}

type reviewResponse struct {
	wantReviewAllow bool
	wantReviewError bool
}

func TestNewValidatingHandlerFunc(t *testing.T) {
	tests := []struct {
		name                    string
		operationMatchesHandler bool
		firstHandlerResponse    *handlerResponse
		secondHandlerResponse   *handlerResponse

		hasDecodeError    bool
		hasMissingRequest bool

		wantHTTPError bool
		wantResponse  *reviewResponse
	}{
		{
			name:                    "handler matches, both allow",
			operationMatchesHandler: true,
			firstHandlerResponse: &handlerResponse{
				hasAllow: true,
			},
			secondHandlerResponse: &handlerResponse{
				hasAllow: true,
			},
			wantResponse: &reviewResponse{
				wantReviewAllow: true,
			},
		},
		{
			name:                    "handler matches, first denies, second allows",
			operationMatchesHandler: true,
			firstHandlerResponse: &handlerResponse{
				hasAllow: false,
			},
			secondHandlerResponse: &handlerResponse{
				hasAllow: true,
			},
			wantResponse: &reviewResponse{
				wantReviewAllow: false,
			},
		},
		{
			name:                    "handler matches, first allows, second denies",
			operationMatchesHandler: true,
			firstHandlerResponse: &handlerResponse{
				hasAllow: true,
			},
			secondHandlerResponse: &handlerResponse{
				hasAllow: false,
			},
			wantResponse: &reviewResponse{
				wantReviewAllow: false,
			},
		},
		{
			name:                    "handler matches, both deny",
			operationMatchesHandler: true,
			firstHandlerResponse: &handlerResponse{
				hasAllow: false,
			},
			secondHandlerResponse: &handlerResponse{
				hasAllow: false,
			},
			wantResponse: &reviewResponse{
				wantReviewAllow: false,
			},
		},
		{
			name:                    "handler matches, first error",
			operationMatchesHandler: true,
			firstHandlerResponse: &handlerResponse{
				hasError: true,
			},
			wantHTTPError: true,
			wantResponse: &reviewResponse{
				wantReviewAllow: false,
				wantReviewError: true,
			},
		},
		{
			name:                    "handler matches, first allow, second error",
			operationMatchesHandler: true,
			firstHandlerResponse: &handlerResponse{
				hasAllow: true,
			},
			secondHandlerResponse: &handlerResponse{
				hasError: true,
			},
			wantHTTPError: true,
			wantResponse: &reviewResponse{
				wantReviewAllow: false,
				wantReviewError: true,
			},
		},
		{
			name:                    "handler doesn't match",
			operationMatchesHandler: false,
			wantHTTPError:           true,
		},
		{
			name:           "decode error",
			hasDecodeError: true,
			wantHTTPError:  true,
		},
		{
			name:           "missing request",
			hasDecodeError: true,
			wantHTTPError:  true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			firstAdmitter := setupAdmitter(test.firstHandlerResponse)
			secondAdmitter := setupAdmitter(test.secondHandlerResponse)
			handler := fakeValidatingAdmissionHandler{
				gvr: schema.GroupVersionResource{
					Group:    "test.cattle.io",
					Version:  "v1alpha1",
					Resource: "resources",
				},
				operations: []v1.OperationType{
					v1.Create,
				},
				admitters: []fakeAdmitter{firstAdmitter, secondAdmitter},
			}
			var bodyBytes []byte
			var err error
			if test.hasMissingRequest {
				review := admissionv1.AdmissionReview{}
				bodyBytes, err = json.Marshal(review)
				assert.NoError(t, err)
			} else if test.hasDecodeError {
				data := map[string]any{
					"request": "value",
				}
				bodyBytes, err = json.Marshal(data)
				assert.NoError(t, err)
			} else {
				review := admissionv1.AdmissionReview{
					Request: &admissionv1.AdmissionRequest{
						Operation: admissionv1.Delete,
						Kind: metav1.GroupVersionKind{
							Group:   "test.cattle.io",
							Version: "v1alpha1",
							Kind:    "Resource",
						},
						Namespace: "test-ns",
						Name:      "test",
						UserInfo: authenticationv1.UserInfo{
							Username: "test-user",
						},
						UID: "1",
					},
				}
				if test.operationMatchesHandler {
					review.Request.Operation = admissionv1.Create
				}
				bodyBytes, err = json.Marshal(review)
				assert.NoError(t, err)
			}
			body := strings.NewReader(string(bodyBytes))
			request := httptest.NewRequest("get", "/testEndpoint", body)
			response := httptest.NewRecorder()
			handlerFunc := admission.NewValidatingHandlerFunc(&handler)
			handlerFunc(response, request)
			if test.wantHTTPError {
				assert.Greater(t, response.Code, 399, "expected an error code of 400 or higher")
			}
			if test.wantResponse != nil {
				review := admissionv1.AdmissionReview{}
				err := json.NewDecoder(response.Result().Body).Decode(&review)
				assert.NoError(t, err)
				assert.Equal(t, types.UID("1"), review.Response.UID)
				assert.Equal(t, test.wantResponse.wantReviewAllow, review.Response.Allowed)
				if test.wantResponse.wantReviewError {
					assert.Greater(t, int(review.Response.Result.Code), 399, "expected an error code of 400 or higher")
				}
			}
		})
	}

}

func TestNewMutatingHandlerFunc(t *testing.T) {
	tests := []struct {
		name                    string
		operationMatchesHandler bool
		handlerResponse         *handlerResponse

		hasDecodeError    bool
		hasMissingRequest bool

		wantHTTPError   bool
		wantReviewAllow bool
		wantResponse    *reviewResponse
	}{
		{
			name:                    "handler matches and allows",
			operationMatchesHandler: true,
			handlerResponse: &handlerResponse{
				hasAllow: true,
			},
			wantResponse: &reviewResponse{
				wantReviewAllow: true,
			},
		},
		{
			name:                    "handler matches and denies",
			operationMatchesHandler: true,
			handlerResponse: &handlerResponse{
				hasAllow: false,
			},
			wantResponse: &reviewResponse{
				wantReviewAllow: false,
			},
		},
		{
			name:                    "handler does not match",
			operationMatchesHandler: false,
			wantResponse: &reviewResponse{
				wantReviewAllow: false,
			},
		},
		{
			name:                    "handler matches but gets an error",
			operationMatchesHandler: true,
			handlerResponse: &handlerResponse{
				hasError: true,
			},
			wantHTTPError: true,
			wantResponse: &reviewResponse{
				wantReviewAllow: false,
				wantReviewError: true,
			},
		},
		{
			name:           "decode error",
			hasDecodeError: true,
			wantHTTPError:  true,
		},
		{
			name:              "missing request",
			hasMissingRequest: true,
			wantHTTPError:     true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			admitter := setupAdmitter(test.handlerResponse)
			handler := fakeMutatingAdmissionHandler{
				gvr: schema.GroupVersionResource{
					Group:    "test.cattle.io",
					Version:  "v1alpha1",
					Resource: "resources",
				},
				operations: []v1.OperationType{
					v1.Create,
				},
				admitter: admitter,
			}
			var bodyBytes []byte
			var err error
			if test.hasMissingRequest {
				review := admissionv1.AdmissionReview{}
				bodyBytes, err = json.Marshal(review)
				assert.NoError(t, err)
			} else if test.hasDecodeError {
				data := map[string]any{
					"request": "value",
				}
				bodyBytes, err = json.Marshal(data)
				assert.NoError(t, err)
			} else {
				review := admissionv1.AdmissionReview{
					Request: &admissionv1.AdmissionRequest{
						Operation: admissionv1.Delete,
						Kind: metav1.GroupVersionKind{
							Group:   "test.cattle.io",
							Version: "v1alpha1",
							Kind:    "Resource",
						},
						Namespace: "test-ns",
						Name:      "test",
						UserInfo: authenticationv1.UserInfo{
							Username: "test-user",
						},
						UID: "1",
					},
				}
				if test.operationMatchesHandler {
					review.Request.Operation = admissionv1.Create
				}
				bodyBytes, err = json.Marshal(review)
				assert.NoError(t, err)
			}
			body := strings.NewReader(string(bodyBytes))
			request := httptest.NewRequest("get", "/testEndpoint", body)
			response := httptest.NewRecorder()
			handlerFunc := admission.NewMutatingHandlerFunc(&handler)
			handlerFunc(response, request)
			if test.wantHTTPError {
				assert.Greater(t, response.Code, 399, "expected an error code of 400 or higher")
			}
			if test.wantResponse != nil {
				review := admissionv1.AdmissionReview{}
				err := json.NewDecoder(response.Result().Body).Decode(&review)
				assert.NoError(t, err)
				assert.Equal(t, types.UID("1"), review.Response.UID)
				assert.Equal(t, test.wantResponse.wantReviewAllow, review.Response.Allowed)
				if test.wantResponse.wantReviewError {
					assert.Greater(t, int(review.Response.Result.Code), 399, "expected an error code of 400 or higher")
				}
			}

		})
	}
}

func setupAdmitter(response *handlerResponse) fakeAdmitter {
	admitter := fakeAdmitter{}
	if response == nil {
		return admitter
	}
	if response.hasError {
		admitter.err = fmt.Errorf("handler/admitter error")
	}
	admitter.response = admissionv1.AdmissionResponse{
		Allowed: response.hasAllow,
	}
	return admitter
}

type fakeValidatingAdmissionHandler struct {
	gvr        schema.GroupVersionResource
	operations []v1.OperationType
	admitters  []fakeAdmitter
}

func (f *fakeValidatingAdmissionHandler) GVR() schema.GroupVersionResource {
	return f.gvr
}
func (f *fakeValidatingAdmissionHandler) Operations() []v1.OperationType {
	return f.operations
}

func (f *fakeValidatingAdmissionHandler) ValidatingWebhook(clientConfig v1.WebhookClientConfig) []v1.ValidatingWebhook {
	return nil
}

func (f *fakeValidatingAdmissionHandler) Admitters() []admission.Admitter {
	var admitters []admission.Admitter
	for _, admitter := range f.admitters {
		admitter := admitter
		admitters = append(admitters, &admitter)
	}
	return admitters
}

type fakeMutatingAdmissionHandler struct {
	gvr        schema.GroupVersionResource
	operations []v1.OperationType
	admitter   fakeAdmitter
}

func (f *fakeMutatingAdmissionHandler) GVR() schema.GroupVersionResource {
	return f.gvr
}
func (f *fakeMutatingAdmissionHandler) Operations() []v1.OperationType {
	return f.operations
}

func (f *fakeMutatingAdmissionHandler) Admit(req *admission.Request) (*admissionv1.AdmissionResponse, error) {
	return f.admitter.Admit(req)
}

func (f *fakeMutatingAdmissionHandler) MutatingWebhook(clientConfig v1.WebhookClientConfig) []v1.MutatingWebhook {
	return nil
}

type fakeAdmitter struct {
	response admissionv1.AdmissionResponse
	err      error
}

func (f *fakeAdmitter) Admit(req *admission.Request) (*admissionv1.AdmissionResponse, error) {
	return &f.response, f.err
}
