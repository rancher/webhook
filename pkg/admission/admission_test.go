// Package admission holds definitions and functions for admissionWebhook.
package admission

import (
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type DummyWebhookHandler struct {
	operations []v1.OperationType
}

func NewDummyWebhookHandler(op []v1.OperationType) *DummyWebhookHandler {
	return &DummyWebhookHandler{operations: op}
}

func (d *DummyWebhookHandler) GVR() schema.GroupVersionResource {
	return schema.GroupVersionResource{
		Group:    "group",
		Version:  "version",
		Resource: "resource",
	}
}

func (d *DummyWebhookHandler) Operations() []v1.OperationType {
	return d.operations
}

func (d *DummyWebhookHandler) Admit(*Request) (*admissionv1.AdmissionResponse, error) {
	return nil, nil
}

type DummyResponseWriter struct {
	header http.Header
	text   string
}

func NewDummyResponseWriter() *DummyResponseWriter {
	return &DummyResponseWriter{http.Header{}, ""}
}

func (d *DummyResponseWriter) Header() http.Header {
	return d.header
}

func (d *DummyResponseWriter) Write(b []byte) (int, error) {
	d.text = d.text + string(b)
	return 0, errors.New("Expected Warning")
}

func (d *DummyResponseWriter) WriteHeader(int) {
}

type ServerSuite struct {
	suite.Suite
}

func TestAdmission(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(ServerSuite))
}

func (p *ServerSuite) TestDefaultValidatingWebhook() {
	handler := new(DummyWebhookHandler)
	clientConfig := v1.WebhookClientConfig{}
	scopeType := v1.ScopeType("scope")

	result := NewDefaultValidatingWebhook(handler, clientConfig, scopeType, nil)
	assert.Equal(p.T(), "rancher.cattle.io.resource.group", result.Name)
	assert.Equal(p.T(), clientConfig, result.ClientConfig)
	assert.NotNil(p.T(), result.Rules)
	assert.Equal(p.T(), v1.FailurePolicyType("Fail"), *result.FailurePolicy)
	assert.Equal(p.T(), v1.MatchPolicyType("Equivalent"), *result.MatchPolicy)
	assert.Equal(p.T(), v1.SideEffectClass("None"), *result.SideEffects)
	assert.Nil(p.T(), result.TimeoutSeconds)
	assert.Equal(p.T(), []string{"v1", "v1beta1"}, result.AdmissionReviewVersions)
}

func (p *ServerSuite) TestDefaultMutatingWebhook() {
	handler := new(DummyWebhookHandler)
	clientConfig := v1.WebhookClientConfig{}
	scopeType := v1.ScopeType("scope")

	result := NewDefaultMutatingWebhook(handler, clientConfig, scopeType, nil)
	assert.Equal(p.T(), "rancher.cattle.io.resource.group", result.Name)
	assert.Equal(p.T(), clientConfig, result.ClientConfig)
	assert.NotNil(p.T(), result.Rules)
	assert.Equal(p.T(), v1.FailurePolicyType("Fail"), *result.FailurePolicy)
	assert.Equal(p.T(), v1.MatchPolicyType("Equivalent"), *result.MatchPolicy)
	assert.Equal(p.T(), v1.SideEffectClass("None"), *result.SideEffects)
	assert.Nil(p.T(), result.TimeoutSeconds)
	assert.Equal(p.T(), []string{"v1", "v1beta1"}, result.AdmissionReviewVersions)
}

func (p *ServerSuite) TestDefaultWebhookInfo() {
	handler := new(DummyWebhookHandler)
	url := "testURL"
	clientConfig := v1.WebhookClientConfig{
		URL: &url,
		Service: &v1.ServiceReference{
			Path: &url,
		},
	}

	scopeType := v1.ScopeType("scope")

	result := defaultWebhookInfo(handler, clientConfig, scopeType, nil)
	assert.Equal(p.T(), scopeType, *result.rules[0].Rule.Scope)
	assert.Equal(p.T(), "rancher.cattle.io.resource.group", result.name)
	assert.Equal(p.T(), "testURL/resource.group", *result.clientConfig.URL)
	assert.Equal(p.T(), "testURL/resource.group", *result.clientConfig.Service.Path)
}

func (p *ServerSuite) TestPath() {
	handler := new(DummyWebhookHandler)
	// ":test"
	tests := []struct {
		name     string
		basePath string
		want     string
	}{
		{
			name:     "Valid URL path",
			basePath: "test",
			want:     "test/resource.group",
		},
		{
			name:     "Invalide URL path",
			basePath: ":test",
			want:     ":test/resource.group",
		},
	}
	for _, tt := range tests {
		p.Run(tt.name, func() {
			path := Path(tt.basePath, handler)
			assert.Equal(p.T(), tt.want, path)
		})
	}
}

func (p *ServerSuite) TestSubPath() {
	tests := []struct {
		name string
		gvr  schema.GroupVersionResource
		want string
	}{
		{
			name: "Subpath of gvr",
			gvr: schema.GroupVersionResource{
				Resource: "resource",
				Group:    "group",
			},
			want: "resource.group",
		},
		{
			name: "Subpath of gvr with wildcard",
			gvr: schema.GroupVersionResource{
				Resource: "*",
				Group:    "group",
			},
			want: "group",
		},
	}
	for _, tt := range tests {
		p.Run(tt.name, func() {
			assert.Equal(p.T(), tt.want, SubPath(tt.gvr))
		})
	}
}

func (p *ServerSuite) TestWriteResponse() {
	writer := NewDummyResponseWriter()
	expectedWriter := NewDummyResponseWriter()
	expectedWriter.Header().Set("Content-Type", "application/json")
	expectedWriter.Write([]byte("{}\n"))

	type args struct {
		responseWriter http.ResponseWriter
		review         *admissionv1.AdmissionReview
	}
	tests := []struct {
		name     string
		args     args
		expected http.ResponseWriter
	}{
		{
			name: "Default test",
			args: args{
				responseWriter: writer,
				review:         &admissionv1.AdmissionReview{},
			},
			expected: expectedWriter,
		},
	}
	for _, tt := range tests {
		p.Run(tt.name, func() {
			writeResponse(tt.args.responseWriter, tt.args.review)
			assert.Equal(p.T(), tt.expected, tt.args.responseWriter)
		})
	}
}

func (p *ServerSuite) TestCanHandleOperation() {
	type args struct {
		operations       []v1.OperationType
		requestOperation admissionv1.Operation
	}
	tests := []struct {
		name      string
		args      args
		canHandle bool
	}{
		{
			name: "Operation is OperationAll",
			args: args{
				operations:       []v1.OperationType{v1.OperationAll},
				requestOperation: "",
			},
			canHandle: true,
		},
		{
			name: "Operation matches request operation",
			args: args{
				operations:       []v1.OperationType{v1.Connect, v1.Create},
				requestOperation: admissionv1.Operation(v1.Create),
			},
			canHandle: true,
		},
		{
			name: "No operation matches request operation",
			args: args{
				operations:       []v1.OperationType{v1.Connect, v1.Create},
				requestOperation: "",
			},
			canHandle: false,
		},
		{
			name: "No operation in list",
			args: args{
				operations:       []v1.OperationType{},
				requestOperation: admissionv1.Operation(v1.OperationAll),
			},
			canHandle: false,
		},
	}
	for _, tt := range tests {
		p.Run(tt.name, func() {
			webhookHandler := NewDummyWebhookHandler(tt.args.operations)
			result := canHandleOperation(webhookHandler, tt.args.requestOperation)
			assert.Equal(p.T(), tt.canHandle, result)
		})
	}
}

func (p *ServerSuite) TestResourceString() {
	type args struct {
		ns   string
		name string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Result with namespace",
			args: args{
				ns:   "ns",
				name: "name",
			},
			want: "ns/name",
		},
		{
			name: "Result with no namespace",
			args: args{
				ns:   "",
				name: "name",
			},
			want: "name",
		},
	}
	for _, tt := range tests {
		p.Run(tt.name, func() {
			assert.Equal(p.T(), tt.want, resourceString(tt.args.ns, tt.args.name))
		})
	}
}

func (p *ServerSuite) TestDefaultResponses() {
	allowed := ResponseAllowed()
	assert.Equal(p.T(), allowed.Allowed, true)

	message := "message"
	badRequest := ResponseBadRequest(message)
	assert.Equal(p.T(), badRequest.Allowed, false)
	assert.Equal(p.T(), badRequest.Result.Status, "Failure")
	assert.Equal(p.T(), badRequest.Result.Message, message)
	assert.Equal(p.T(), badRequest.Result.Reason, metav1.StatusReasonBadRequest)
	assert.Equal(p.T(), badRequest.Result.Code, int32(http.StatusBadRequest))
}

func (p *ServerSuite) TestCreateWebhookName() {
	webhookHandler := new(DummyWebhookHandler)

	type args struct {
		handler WebhookHandler
		suffix  string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "Result with suffix",
			args: args{
				handler: webhookHandler,
				suffix:  "suffix",
			},
			want: "rancher.cattle.io.resource.group.suffix",
		},
		{
			name: "Result with no suffix",
			args: args{
				handler: webhookHandler,
				suffix:  "",
			},
			want: "rancher.cattle.io.resource.group",
		},
	}
	for _, tt := range tests {
		p.Run(tt.name, func() {
			result := CreateWebhookName(tt.args.handler, tt.args.suffix)
			assert.Equal(p.T(), tt.want, result)
		})
	}
}
