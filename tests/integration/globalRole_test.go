package integration_test

import (
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (m *IntegrationSuite) TestGlobalRole() {
	newObj := func() *v3.GlobalRole { return &v3.GlobalRole{} }
	validCreateObj := &v3.GlobalRole{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-globalrole",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"GET", "WATCH"},
				APIGroups: []string{"v1"},
				Resources: []string{"pods"},
			},
		},
	}
	invalidCreate := func() *v3.GlobalRole {
		invalidCreate := validCreateObj.DeepCopy()
		if len(invalidCreate.Rules) != 0 {
			invalidCreate.Rules[0].Verbs = nil
		}
		return invalidCreate
	}
	invalidUpdate := func(created *v3.GlobalRole) *v3.GlobalRole {
		invalidUpdateObj := created.DeepCopy()
		if len(invalidUpdateObj.Rules) != 0 {
			invalidUpdateObj.Rules[0].Verbs = nil
		}
		return invalidUpdateObj
	}
	validUpdate := func(created *v3.GlobalRole) *v3.GlobalRole {
		validUpdateObj := created.DeepCopy()
		validUpdateObj.Description = "Updated description"
		return validUpdateObj
	}
	validDelete := func() *v3.GlobalRole {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.GlobalRole]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}

func (m *IntegrationSuite) TestGlobalRoleNoResources() {
	newObj := func() *v3.GlobalRole { return &v3.GlobalRole{} }
	validCreateObj := &v3.GlobalRole{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-globalrole-no-resources",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"GET", "WATCH"},
				APIGroups: []string{"v1"},
				Resources: []string{"pods"},
			},
		},
	}
	invalidCreate := func() *v3.GlobalRole {
		invalidCreate := validCreateObj.DeepCopy()
		if len(invalidCreate.Rules) != 0 {
			invalidCreate.Rules[0].Resources = nil
		}
		return invalidCreate
	}
	validDelete := func() *v3.GlobalRole {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.GlobalRole]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}

func (m *IntegrationSuite) TestGlobalRoleNoAPIGroups() {
	newObj := func() *v3.GlobalRole { return &v3.GlobalRole{} }
	validCreateObj := &v3.GlobalRole{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-globalrole-no-apigroups",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"GET", "WATCH"},
				APIGroups: []string{"v1"},
				Resources: []string{"pods"},
			},
		},
	}
	invalidCreate := func() *v3.GlobalRole {
		invalidCreate := validCreateObj.DeepCopy()
		if len(invalidCreate.Rules) != 0 {
			invalidCreate.Rules[0].APIGroups = nil
		}
		return invalidCreate
	}
	validDelete := func() *v3.GlobalRole {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.GlobalRole]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}
