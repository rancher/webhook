package integration_test

import (
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (m *IntegrationSuite) TestProxyEndpoints() {
	newObj := func() *v3.ProxyEndpoint { return &v3.ProxyEndpoint{} }

	validCreate := &v3.ProxyEndpoint{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-proxy-endpoint",
		},
		Spec: v3.ProxyEndpointSpec{
			Routes: []v3.ProxyEndpointRoute{
				{
					Domain: "example.com",
				},
			},
		},
	}

	endPoints := &endPointObjs[*v3.ProxyEndpoint]{
		invalidCreate: func() *v3.ProxyEndpoint {
			return &v3.ProxyEndpoint{
				ObjectMeta: v1.ObjectMeta{
					Name: "test-proxy-endpoint",
				},
				Spec: v3.ProxyEndpointSpec{
					Routes: []v3.ProxyEndpointRoute{
						{
							Domain: "*.com",
						},
					},
				},
			}
		},
		newObj:         newObj,
		validCreateObj: validCreate,
		invalidUpdate: func(obj *v3.ProxyEndpoint) *v3.ProxyEndpoint {
			invalid := obj.DeepCopy()
			invalid.Spec.Routes = []v3.ProxyEndpointRoute{
				{
					Domain: "*.com",
				},
			}
			return invalid
		},
		validUpdate: func(obj *v3.ProxyEndpoint) *v3.ProxyEndpoint {
			valid := obj.DeepCopy()
			valid.Spec.Routes = []v3.ProxyEndpointRoute{
				{
					Domain: "other.com",
				},
			}
			return valid
		},
		validDelete: func() *v3.ProxyEndpoint {
			return validCreate
		},
	}

	validateEndpoints(m.T(), endPoints, m.clientFactory)
}
