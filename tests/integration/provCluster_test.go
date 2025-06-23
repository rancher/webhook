package integration_test

import (
	provisioningv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/resources/common"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (m *IntegrationSuite) TestProvisioningCluster() {
	newObj := func() *provisioningv1.Cluster { return &provisioningv1.Cluster{} }
	validCreateObj := &provisioningv1.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: m.testnamespace,
		},
	}
	invalidCreate := func() *provisioningv1.Cluster {
		invalidCreate := validCreateObj.DeepCopy()
		invalidCreate.Name = "local"
		return invalidCreate
	}
	invalidUpdate := func(created *provisioningv1.Cluster) *provisioningv1.Cluster {
		invalidUpdateObj := created.DeepCopy()
		invalidUpdateObj.Annotations = map[string]string{common.CreatorIDAnn: "foobar"}
		return invalidUpdateObj
	}
	validUpdate := func(created *provisioningv1.Cluster) *provisioningv1.Cluster {
		validUpdateObj := created.DeepCopy()
		validUpdateObj.Spec.KubernetesVersion = "v1.25"
		return validUpdateObj
	}
	validDelete := func() *provisioningv1.Cluster {
		return validCreateObj
	}
	endPoints := &endPointObjs[*provisioningv1.Cluster]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}
