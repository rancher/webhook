package integration_test

import (
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (m *IntegrationSuite) TestGlobalRoleBinding() {
	const grName = "grb-testgr"
	newObj := func() *v3.GlobalRoleBinding { return &v3.GlobalRoleBinding{} }
	validCreateObj := &v3.GlobalRoleBinding{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-globalrolebinding",
		},
		GlobalRoleName: grName,
	}
	invalidCreate := func() *v3.GlobalRoleBinding {
		invalidCreate := validCreateObj.DeepCopy()
		invalidCreate.GlobalRoleName = "foo"
		return invalidCreate
	}
	invalidUpdate := func(created *v3.GlobalRoleBinding) *v3.GlobalRoleBinding {
		invalidUpdateObj := created.DeepCopy()
		invalidUpdateObj.GlobalRoleName = "foo"
		return invalidUpdateObj
	}
	validUpdate := func(created *v3.GlobalRoleBinding) *v3.GlobalRoleBinding {
		validUpdateObj := created.DeepCopy()
		if validUpdateObj.Annotations == nil {
			validUpdateObj.Annotations = map[string]string{"foo": "bar"}
		} else {
			validUpdateObj.Annotations["foo"] = "bar"
		}
		return validUpdateObj
	}
	validDelete := func() *v3.GlobalRoleBinding {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.GlobalRoleBinding]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}

	testGR := &v3.GlobalRole{
		ObjectMeta: v1.ObjectMeta{
			Name: grName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"GET", "WATCH"},
				APIGroups: []string{"v1"},
				Resources: []string{"pods"},
			},
		},
	}
	m.createObj(testGR, schema.GroupVersionKind{})
	validateEndpoints(m.T(), endPoints, m.clientFactory)
	m.deleteObj(testGR, schema.GroupVersionKind{})
}
