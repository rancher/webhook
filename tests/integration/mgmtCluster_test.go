package integration_test

import (
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rke/types"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (m *IntegrationSuite) TestManagementCluster() {
	newObj := func() *v3.Cluster { return &v3.Cluster{} }
	validCreateObj := &v3.Cluster{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-cluster",
		},
		Spec: v3.ClusterSpec{
			ClusterSpecBase: v3.ClusterSpecBase{
				RancherKubernetesEngineConfig: &types.RancherKubernetesEngineConfig{},
			},
		},
	}

	validDelete := func() *v3.Cluster {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.Cluster]{
		invalidCreate:  nil,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  nil,
		validUpdate:    nil,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}
