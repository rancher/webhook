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
	"k8s.io/apimachinery/pkg/runtime/schema"
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

	// Admit handles the webhook admission request sent to this webhook.
	// The response returned by the WebhookHandler will be forwarded to the kube-api server.
	// If the WebhookHandler can not accurately evaluate the request it should return an error.
	Admit(*Request) (*admissionv1.AdmissionResponse, error)
}

// ValidatingAdmissionHandler is a handler used for creating a ValidationAdmission Webhook.
type ValidatingAdmissionHandler interface {
	WebhookHandler

	// ValidatingWebhook returns the configuration information for a ValidatingWebhook.
	// This functions allows ValidatingAdmissionHandler to perform and modifications to the default configuration if needed.
	// A default configuration can be made using NewDefaultValidatingWebhook(...)
	ValidatingWebhook(clientConfig v1.WebhookClientConfig) *v1.ValidatingWebhook
}

// MutatingAdmissionHandler is a handler used for creating a MutatingAdmission Webhook.
type MutatingAdmissionHandler interface {
	WebhookHandler

	// MutatingWebhook returns the configuration information for a ValidatingWebhook.
	// This functions allows MutatingAdmissionHandler to perform and modifications to the default configuration if needed.
	// A default configuration can be made using NewDefaultMutatingWebhook(...)
	MutatingWebhook(clientConfig v1.WebhookClientConfig) *v1.MutatingWebhook
}

// Request is a simple wrapper for an AdmissionRequest that includes the context from the original http.Request.
type Request struct {
	admissionv1.AdmissionRequest
	Context context.Context
}

// NewDefaultValidatingWebhook creates a new ValidatingWebhook based on the WebhookHandler provided.
// The path set on the client config will be appended with the webhooks path.
// The return webhook will not be nil.
func NewDefaultValidatingWebhook(handler WebhookHandler, clientConfig v1.WebhookClientConfig, scope v1.ScopeType) *v1.ValidatingWebhook {
	info := defaultWebhookInfo(handler, clientConfig, scope)
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
func NewDefaultMutatingWebhook(handler WebhookHandler, clientConfig v1.WebhookClientConfig, scope v1.ScopeType) *v1.MutatingWebhook {
	info := defaultWebhookInfo(handler, clientConfig, scope)
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
func defaultWebhookInfo(handler WebhookHandler, clientConfig v1.WebhookClientConfig, scope v1.ScopeType) webhookInfo {
	gvr := handler.GVR()
	rules := []v1.RuleWithOperations{
		{
			Operations: handler.Operations(),
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
		name:         fmt.Sprintf("rancher.cattle.io.%s", SubPath(gvr)),
		clientConfig: clientConfig,
		rules:        rules,
	}
}

// Path returns the path of the webhook joined with the given basePath.
func Path(basePath string, handler WebhookHandler) string {
	gvr := handler.GVR()
	newPath, err := url.JoinPath(basePath, SubPath(gvr))
	if err != nil {
		return path.Join(basePath, SubPath(gvr))
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

// NewHandlerFunc returns a new HandlerFunc that will call the WebhookHandler's admit function.
func NewHandlerFunc(handler WebhookHandler) http.HandlerFunc {
	return func(responseWriter http.ResponseWriter, req *http.Request) {
		review := &admissionv1.AdmissionReview{}
		err := json.NewDecoder(req.Body).Decode(review)
		if err != nil {
			sendError(responseWriter, review, err)
			return
		}

		if review.Request == nil {
			sendError(responseWriter, review, fmt.Errorf("request is not set: %w", ErrInvalidRequest))
			return
		}
		webReq := &Request{
			AdmissionRequest: *review.Request,
			Context:          req.Context(),
		}

		// validate that this handler can handle the provided operation.
		if !canHandleOperation(handler, review.Request.Operation) {
			sendError(responseWriter, review, fmt.Errorf("can not handle '%s' for '%s': %w", review.Request.Operation, SubPath(handler.GVR()), ErrUnsupportedOperation))
			return
		}

		review.Response, err = handler.Admit(webReq)
		if review.Response == nil {
			review.Response = &admissionv1.AdmissionResponse{}
		}
		logrus.Debugf("admit result: %s %s %s user=%s allowed=%v err=%v", webReq.Operation, webReq.Kind.String(), resourceString(webReq.Namespace, webReq.Name), webReq.UserInfo.Username, review.Response.Allowed, err)
		if err != nil {
			sendError(responseWriter, review, err)
			return
		}

		review.Response.UID = review.Request.UID
		writeResponse(responseWriter, review)
	}
}

// Ptr is a generic function that returns the pointer of a string.
func Ptr[T ~string](str T) *T {
	newStr := str
	return &newStr
}

func sendError(responseWriter http.ResponseWriter, review *admissionv1.AdmissionReview, err error) {
	logrus.Error(err)
	if review == nil || review.Request == nil {
		http.Error(responseWriter, err.Error(), http.StatusInternalServerError)
		return
	}
	review.Response.Result = &errors.NewInternalError(err).ErrStatus
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
