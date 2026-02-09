package proxyendpoint

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/stretchr/testify/suite"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type ProxyEndpointValidationSuite struct {
	suite.Suite
}

func TestProxyEndpointValidation(t *testing.T) {
	t.Parallel()
	suite.Run(t, new(ProxyEndpointValidationSuite))
}

func newProxyEndpoint(routes []string) []byte {
	endpoint := v3.ProxyEndpoint{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test",
		},
		Spec: v3.ProxyEndpointSpec{},
	}
	for _, domain := range routes {
		endpoint.Spec.Routes = append(endpoint.Spec.Routes, v3.ProxyEndpointRoute{Domain: domain})
	}
	b, _ := json.Marshal(endpoint)
	return b
}

func (suite *ProxyEndpointValidationSuite) TestStandardWildcard() {
	a := admitter{}
	tests := []struct {
		endpoint []byte
		allowed  bool
	}{
		{
			endpoint: newProxyEndpoint([]string{"*.example.com"}),
			allowed:  true,
		},
		{
			endpoint: newProxyEndpoint([]string{"*example.com"}),
			allowed:  true,
		},
		{
			endpoint: newProxyEndpoint([]string{"%.example.com"}),
			allowed:  true,
		},
		{
			endpoint: newProxyEndpoint([]string{"myapi.%.org"}),
			allowed:  false,
		},
		{
			endpoint: newProxyEndpoint([]string{"myapi.%.co.uk"}),
			allowed:  false,
		},
		{
			endpoint: newProxyEndpoint([]string{"*.myapi.%.co.uk"}),
			allowed:  false,
		},
	}

	for _, test := range tests {
		resp, err := a.Admit(&admission.Request{
			Context: context.Background(),
			AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: test.endpoint,
				},
			},
		})
		suite.Nil(err)
		suite.Equal(test.allowed, resp.Allowed, fmt.Sprintf("admission request returned unexpected allowed value for endpoint with routes %s, expected %t, got %t", string(test.endpoint), test.allowed, resp.Allowed))
	}
}

func (suite *ProxyEndpointValidationSuite) TestOverlyBroadWithoutTLD() {
	a := admitter{}
	tests := []struct {
		endpoint []byte
		allowed  bool
	}{
		{
			endpoint: newProxyEndpoint([]string{"*"}),
			allowed:  false,
		},
		{
			endpoint: newProxyEndpoint([]string{"%"}),
			allowed:  false,
		},
	}

	for _, test := range tests {
		resp, err := a.Admit(&admission.Request{
			Context: context.Background(),
			AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: test.endpoint,
				},
			},
		})
		suite.Nil(err)
		suite.Equal(test.allowed, resp.Allowed, fmt.Sprintf("admission request returned unexpected allowed value for endpoint with routes %v, expected %t, got %t", test.endpoint, test.allowed, resp.Allowed))
	}
}

func (suite *ProxyEndpointValidationSuite) TestOverlyBroadWithTLD() {
	a := admitter{}

	tests := []struct {
		endpoint []byte
		allowed  bool
	}{
		{
			endpoint: newProxyEndpoint([]string{"*.com"}),
			allowed:  false,
		},
		{
			endpoint: newProxyEndpoint([]string{"%.com"}),
			allowed:  false,
		},
		{
			endpoint: newProxyEndpoint([]string{"*.org"}),
			allowed:  false,
		},
		{
			endpoint: newProxyEndpoint([]string{"%.org"}),
			allowed:  false,
		},
	}

	for _, test := range tests {
		resp, err := a.Admit(&admission.Request{
			Context: context.Background(),
			AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: test.endpoint,
				},
			},
		})
		suite.Nil(err)
		suite.Equal(test.allowed, resp.Allowed, fmt.Sprintf("admission request returned unexpected allowed value for endpoint with routes %v, expected %t, got %t", test.endpoint, test.allowed, resp.Allowed))
	}
}

func (suite *ProxyEndpointValidationSuite) TestOverlyBroadWithMultiPartTLD() {
	a := admitter{}
	tests := []struct {
		endpoint []byte
		allowed  bool
	}{
		{
			endpoint: newProxyEndpoint([]string{"*.co.uk"}),
			allowed:  false,
		},
		{
			endpoint: newProxyEndpoint([]string{"%.co.uk"}),
			allowed:  false,
		},
	}
	for _, test := range tests {
		resp, err := a.Admit(&admission.Request{
			Context: context.Background(),
			AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: test.endpoint,
				},
			},
		})
		suite.Nil(err)
		suite.Equal(test.allowed, resp.Allowed, fmt.Sprintf("admission request returned unexpected allowed value for endpoint with routes %v, expected %t, got %t", test.endpoint, test.allowed, resp.Allowed))
	}
}

func (suite *ProxyEndpointValidationSuite) TestNonUpdateOrCreateAllowsInvalidDomains() {
	a := admitter{}
	tests := []struct {
		endpoint []byte
	}{
		{
			endpoint: newProxyEndpoint([]string{"*"}),
		},
		{
			endpoint: newProxyEndpoint([]string{"%.com"}),
		},
		{
			endpoint: newProxyEndpoint([]string{"*.co.uk"}),
		},
		{
			endpoint: newProxyEndpoint([]string{"%.co.uk"}),
		},
		{
			endpoint: newProxyEndpoint([]string{"subdomain.%.org"}),
		},
		{
			endpoint: newProxyEndpoint([]string{"subdomain.%.co.uk"}),
		},
	}

	for _, test := range tests {
		for _, operation := range []admissionv1.Operation{admissionv1.Connect, admissionv1.Delete} {
			resp, err := a.Admit(&admission.Request{
				Context: context.Background(),
				AdmissionRequest: admissionv1.AdmissionRequest{
					Operation: operation,
					Object: runtime.RawExtension{
						Raw: test.endpoint,
					},
				},
			})
			suite.Nil(err)
			suite.Equal(true, resp.Allowed, fmt.Sprintf("admission request returned unexpected allowed value for endpoint with routes %v, expected %t, got %t", test.endpoint, true, resp.Allowed))
		}
	}
}

func (suite *ProxyEndpointValidationSuite) TestStandardDomains() {
	a := admitter{}
	tests := []struct {
		allowed  bool
		endpoint []byte
	}{
		{
			endpoint: newProxyEndpoint([]string{"example.com"}),
			allowed:  true,
		},
		{
			endpoint: newProxyEndpoint([]string{"myapi.example.com"}),
			allowed:  true,
		},
		{
			endpoint: newProxyEndpoint([]string{"myapi.co.uk"}),
			allowed:  true,
		},
	}
	for _, test := range tests {
		resp, err := a.Admit(&admission.Request{
			Context: context.Background(),
			AdmissionRequest: admissionv1.AdmissionRequest{
				Operation: admissionv1.Create,
				Object: runtime.RawExtension{
					Raw: test.endpoint,
				},
			},
		})
		suite.Nil(err)
		suite.Equal(test.allowed, resp.Allowed, fmt.Sprintf("admission request returned unexpected allowed value for endpoint with routes %v, expected %t, got %t", test.endpoint, test.allowed, resp.Allowed))
	}
}
