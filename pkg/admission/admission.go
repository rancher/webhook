// Package admission holds definitions and functions for admissionWebhook.
package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	webhookQualifier     = "rancher.cattle.io"
	bypassServiceAccount = "system:serviceaccount:cattle-system:rancher-webhook-sudo"
	systemMasters        = "system:masters"
)

var (
	// ErrInvalidRequest error returned when the requested operation with the requested fields are invalid.
	ErrInvalidRequest = fmt.Errorf("invalid request")
	// ErrUnsupportedOperation error returned when a validator is unable to validate the received operation.
	ErrUnsupportedOperation = fmt.Errorf("unsupported operation")
	// SlowTraceDuration duration to use when determining if a webhookHandler is slow.
	SlowTraceDuration = time.Second * 2
)

// WebhookHandler base interface for both ValidatingAdmissionHandler and MutatingAdmissionHandler.
// WebhookHandler is used for creating new http.HandlerFunc for each Webhook.
type WebhookHandler interface {
	// GVR returns GroupVersionResource that the Webhook reviews.
	// The returned GVR is used to define the route for accessing this webhook as well as creating the Webhooks Name.
	// Thus the GVR returned must be unique from other WebhookHandlers of the same type e.g.(Mutating or Validating).
	// If a WebhookHandler desires to monitor all resources in a group the Resource defined int he GVR should be "*".
	// If a WebhookHandler desires to monitor a core type the Group can be left empty "".
	GVR() schema.GroupVersionResource

	// Operations returns list of operations that this WebhookHandler supports.
	// Handlers will only be sent request with operations that are contained in the provided list.
	Operations() []v1.OperationType
}

// Admitter handles webhook admission requests sent to this webhook.
// The response returned by the WebhookHandler will be forwarded to the kube-api server.
// If the WebhookHandler can not accurately evaluate the request it should return an error.
type Admitter interface {
	Admit(*Request) (*admissionv1.AdmissionResponse, error)
}

// ValidatingAdmissionHandler is a handler used for creating a ValidationAdmission Webhook.
type ValidatingAdmissionHandler interface {
	WebhookHandler

	// ValidatingWebhook returns a list of configurations to route to this handler.
	//
	// This functions allows ValidatingAdmissionHandler to perform modifications to the default configuration if needed.
	// A default configuration can be made using NewDefaultValidatingWebhook(...)
	// Most Webhooks implementing ValidatingWebhook will only return one configuration.
	ValidatingWebhook(clientConfig v1.WebhookClientConfig) []v1.ValidatingWebhook

	// Admitters returns the admitters that this handler will call when evaluating a resource. If any one of these
	// fails or encounters an error, the failure/error is immediately returned and the rest are short-circuted.
	Admitters() []Admitter
}

// MutatingAdmissionHandler is a handler used for creating a MutatingAdmission Webhook.
type MutatingAdmissionHandler interface {
	WebhookHandler
	// Since mutators can change a resource, each MutatingAdmissionHandler can only use 1 admit function.
	Admitter

	// MutatingWebhook returns a list of configurations to route to this handler.
	//
	// MutatingWebhook functions allows MutatingAdmissionHandler to perform modifications to the default configuration if needed.
	// A default configuration can be made using NewDefaultMutatingWebhook(...)
	// Most Webhooks implementing MutatingWebhook will only return one configuration.
	MutatingWebhook(clientConfig v1.WebhookClientConfig) []v1.MutatingWebhook
}

// Request is a simple wrapper for an AdmissionRequest that includes the context from the original http.Request.
type Request struct {
	admissionv1.AdmissionRequest
	Context context.Context
}

// NewDefaultValidatingWebhook creates a new ValidatingWebhook based on the WebhookHandler provided.
// The path set on the client config will be appended with the webhooks path.
// The return webhook will not be nil.
func NewDefaultValidatingWebhook(handler WebhookHandler, clientConfig v1.WebhookClientConfig, scope v1.ScopeType, ops []v1.OperationType) *v1.ValidatingWebhook {
	info := defaultWebhookInfo(handler, clientConfig, scope, ops)
	return &v1.ValidatingWebhook{
		Name:                    info.name,
		ClientConfig:            info.clientConfig,
		Rules:                   info.rules,
		FailurePolicy:           Ptr(v1.Fail),
		MatchPolicy:             Ptr(v1.Equivalent),
		SideEffects:             Ptr(v1.SideEffectClassNone),
		TimeoutSeconds:          nil,
		AdmissionReviewVersions: []string{"v1", "v1beta1"},
	}
}

// NewDefaultMutatingWebhook creates a new MutatingWebhook based on the WebhookHandler provided.
// The path set on the client config will be appended with the webhooks path.
// The return webhook will not be nil.
func NewDefaultMutatingWebhook(handler WebhookHandler, clientConfig v1.WebhookClientConfig, scope v1.ScopeType, ops []v1.OperationType) *v1.MutatingWebhook {
	info := defaultWebhookInfo(handler, clientConfig, scope, ops)
	return &v1.MutatingWebhook{
		Name:                    info.name,
		ClientConfig:            info.clientConfig,
		Rules:                   info.rules,
		FailurePolicy:           Ptr(v1.Fail),
		MatchPolicy:             Ptr(v1.Equivalent),
		SideEffects:             Ptr(v1.SideEffectClassNone),
		TimeoutSeconds:          nil,
		AdmissionReviewVersions: []string{"v1", "v1beta1"},
	}
}

type webhookInfo struct {
	name         string
	clientConfig v1.WebhookClientConfig
	rules        []v1.RuleWithOperations
}

// defaultWebhookInfo contains common code for creating MutatingWebhooks and ValidatingWebhooks.
func defaultWebhookInfo(handler WebhookHandler, clientConfig v1.WebhookClientConfig, scope v1.ScopeType, ops []v1.OperationType) webhookInfo {
	gvr := handler.GVR()
	rules := []v1.RuleWithOperations{
		{
			Operations: ops,
			Rule: v1.Rule{
				APIGroups:   []string{gvr.Group},
				APIVersions: []string{gvr.Version},
				Resources:   []string{gvr.Resource},
				Scope:       &scope,
			},
		},
	}
	if clientConfig.URL != nil {
		newURL := Path(*clientConfig.URL, handler)
		clientConfig.URL = &newURL
	}
	if clientConfig.Service != nil && clientConfig.Service.Path != nil {
		newService := clientConfig.Service.DeepCopy()
		newPath := Path(*newService.Path, handler)
		newService.Path = &newPath
		clientConfig.Service = newService
	}
	return webhookInfo{
		name:         CreateWebhookName(handler, ""),
		clientConfig: clientConfig,
		rules:        rules,
	}
}

type Pather interface {
	Path() string
}

// Path returns the path of the webhook joined with the given basePath.
func Path(basePath string, handler WebhookHandler) string {
	var resource string
	if pather, ok := handler.(Pather); ok {
		resource = pather.Path()
	} else {
		resource = SubPath(handler.GVR())
	}
	newPath, err := url.JoinPath(basePath, resource)
	if err != nil {
		return path.Join(basePath, resource)
	}
	return newPath
}

// SubPath returns the subpath to use for the given gvr.
func SubPath(gvr schema.GroupVersionResource) string {
	if gvr.Resource == "*" {
		return gvr.Group
	}
	return gvr.GroupResource().String()
}

// NewValidatingHandlerFunc returns a new HandlerFunc that will call the functions returned by the ValidatingAdmissionHandler's AdmitFuncs() call.
// If it encounters a failure or an error, it short-circuts and returns immediately.
func NewValidatingHandlerFunc(handler ValidatingAdmissionHandler) http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, req *http.Request) {
		review, webReq, err := getReviewAndRequestForHandler(req, handler)
		if err != nil {
			sendError(responseWriter, review, err)
			return
		}

		if bypassValidation(review.Request) {
			sendResponse(responseWriter, review, ResponseAllowed())
			logrus.Debugf("admit bypassed: %s %s %s", webReq.Operation, webReq.Kind.String(), resourceString(webReq.Namespace, webReq.Name))
			return
		}

		// save the response from the loop so we can return on success
		var response *admissionv1.AdmissionResponse
		for _, admitter := range handler.Admitters() {
			if admitter == nil {
				continue
			}
			response, err = admitter.Admit(webReq)
			if response == nil {
				response = &admissionv1.AdmissionResponse{}
			}
			logrus.Debugf("admit result: %s %s %s user=%s allowed=%v err=%v", webReq.Operation, webReq.Kind.String(), resourceString(webReq.Namespace, webReq.Name), webReq.UserInfo.Username, response.Allowed, err)

			// if we get an error or are not allowed, short circuit the admits
			if err != nil {
				review.Response = response
				sendError(responseWriter, review, err)
				return
			}
			if !response.Allowed {
				sendResponse(responseWriter, review, response)
				return
			}
		}
		// if we have reached this point, all admits approved
		sendResponse(responseWriter, review, response)
	}
}

// NewMutatingHandlerFunc returns a new HandlerFunc that will call the function returned by the MutatingAdmissionHandler's AdmitFunc() call.
func NewMutatingHandlerFunc(handler MutatingAdmissionHandler) http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, req *http.Request) {
		review, webReq, err := getReviewAndRequestForHandler(req, handler)
		if err != nil {
			// review could not be valid, so initialize some safe defaults
			sendError(responseWriter, review, err)
			return
		}

		if bypassValidation(review.Request) {
			sendResponse(responseWriter, review, ResponseAllowed())
			logrus.Debugf("admit bypassed: %s %s %s", webReq.Operation, webReq.Kind.String(), resourceString(webReq.Namespace, webReq.Name))
			return
		}

		response, err := handler.Admit(webReq)
		if response == nil {
			response = &admissionv1.AdmissionResponse{}
		}
		logrus.Debugf("admit result: %s %s %s user=%s allowed=%v err=%v", webReq.Operation, webReq.Kind.String(), resourceString(webReq.Namespace, webReq.Name), webReq.UserInfo.Username, response.Allowed, err)

		if err != nil {
			review.Response = response
			sendError(responseWriter, review, err)
			return
		}
		sendResponse(responseWriter, review, response)
	}
}

// getReviewAndRequestForHandler produces a admission.AdmissionReview and a Request for a given http request and handler.
// Returns an error if this handler can't handle this request or if the http.Request couldn't be decoded into an admissionReview.
func getReviewAndRequestForHandler(req *http.Request, handler WebhookHandler) (*admissionv1.AdmissionReview, *Request, error) {
	review := admissionv1.AdmissionReview{}
	err := json.NewDecoder(req.Body).Decode(&review)
	if err != nil {
		return nil, nil, err
	}

	if review.Request == nil {
		return &review, nil, fmt.Errorf("request is not set: %w", ErrInvalidRequest)
	}
	webReq := &Request{
		AdmissionRequest: *review.Request,
		Context:          req.Context(),
	}

	// validate that this handler can handle the provided operation
	if !canHandleOperation(handler, review.Request.Operation) {
		return &review, nil, fmt.Errorf("can not handle '%s' for '%s': %w", review.Request.Operation, SubPath(handler.GVR()), ErrUnsupportedOperation)
	}
	return &review, webReq, nil
}

// Ptr is a generic function that returns the pointer of T.
func Ptr[T any](value T) *T {
	newVal := value
	return &newVal
}

func sendResponse(responseWriter http.ResponseWriter, review *admissionv1.AdmissionReview, response *admissionv1.AdmissionResponse) {
	review.Response = response
	review.Response.UID = review.Request.UID
	writeResponse(responseWriter, review)
}

func sendError(responseWriter http.ResponseWriter, review *admissionv1.AdmissionReview, err error) {
	logrus.Error(err)
	if review == nil || review.Request == nil {
		http.Error(responseWriter, err.Error(), http.StatusInternalServerError)
		return
	}
	if review.Response == nil {
		review.Response = &admissionv1.AdmissionResponse{}
	}
	// set the response to 500 so that k8s knows that the request got an error. If we just set the Result status the
	// failure policy won't apply
	responseWriter.WriteHeader(http.StatusInternalServerError)
	review.Response.UID = review.Request.UID

	review.Response.Result = &errors.NewInternalError(err).ErrStatus
	review.Response.Result.Code = http.StatusInternalServerError
	writeResponse(responseWriter, review)
}

func writeResponse(responseWriter http.ResponseWriter, review *admissionv1.AdmissionReview) {
	responseWriter.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(responseWriter).Encode(review)
	if err != nil {
		logrus.Warnf("failed to encode response: %s", err)
	}
}

// canHandleOperation returns true if the given handler lists the operation in the request as a supported operation.
func canHandleOperation(handler WebhookHandler, requestOperation admissionv1.Operation) bool {
	for _, op := range handler.Operations() {
		if string(op) == string(requestOperation) || op == v1.OperationAll {
			return true
		}
	}
	return false
}

// resourceString returns the resource formatted as a string.
func resourceString(ns, name string) string {
	if ns == "" {
		return name
	}
	return fmt.Sprintf("%s/%s", ns, name)
}

// ResponseAllowed returns a minimal AdmissionResponse in which Allowed is true
func ResponseAllowed() *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Allowed: true,
	}
}

// ResponseBadRequest returns an AdmissionResponse for BadRequest(err code 400)
// the message is used as the message in the response
func ResponseBadRequest(message string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Result: &metav1.Status{
			Status:  "Failure",
			Message: message,
			Reason:  metav1.StatusReasonBadRequest,
			Code:    http.StatusBadRequest,
		},
		Allowed: false,
	}
}

// ResponseFailedEscalation returns an AdmissionResponse a failed escalation check.
func ResponseFailedEscalation(message string) *admissionv1.AdmissionResponse {
	return &admissionv1.AdmissionResponse{
		Result: &metav1.Status{
			Status:  "Failure",
			Message: message,
			Reason:  metav1.StatusReasonForbidden,
			Code:    http.StatusForbidden,
		},
		Allowed: false,
	}
}

// CreateWebhookName returns a new name for the given webhook handler with the given suffix.
func CreateWebhookName(handler WebhookHandler, suffix string) string {
	subPath := SubPath(handler.GVR())
	if suffix == "" {
		return fmt.Sprintf("%s.%s", webhookQualifier, subPath)
	}
	return fmt.Sprintf("%s.%s.%s", webhookQualifier, subPath, suffix)
}

// bypassValidation users can bypass the webhook if they are the sudo account and system:masters group
func bypassValidation(request *admissionv1.AdmissionRequest) bool {
	if request.UserInfo.Username != bypassServiceAccount {
		return false
	}
	for _, group := range request.UserInfo.Groups {
		if group == systemMasters {
			return true
		}
	}
	return false
}
