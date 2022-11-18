package integration_test

import (
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (m *IntegrationSuite) TestFeatureEndpoints() {
	newObj := func() *v3.Feature { return &v3.Feature{} }
	validCreateObj := &v3.Feature{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-feature",
		},
		Spec: v3.FeatureSpec{Value: Ptr(false)},
		Status: v3.FeatureStatus{
			LockedValue: Ptr(false),
			Description: "status description",
		},
	}
	invalidUpdate := func(created *v3.Feature) *v3.Feature {
		invalidUpdateObj := created.DeepCopy()
		invalidUpdateObj.Spec.Value = Ptr(true)
		return invalidUpdateObj
	}
	validUpdate := func(created *v3.Feature) *v3.Feature {
		validUpdateObj := created.DeepCopy()
		validUpdateObj.Status.Description = "Updated description"
		return validUpdateObj
	}
	validDelete := func() *v3.Feature {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.Feature]{
		invalidCreate:  nil,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}
