package integration_test

import (
	"context"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func (m *IntegrationSuite) TestRoleTemplate() {
	newObj := func() *v3.RoleTemplate { return &v3.RoleTemplate{} }
	validCreateObj := &v3.RoleTemplate{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-roletemplate",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"GET", "WATCH"},
				APIGroups: []string{"v1"},
				Resources: []string{"pods"},
			},
		},
	}
	invalidCreate := func() *v3.RoleTemplate {
		invalidCreate := validCreateObj.DeepCopy()
		if len(invalidCreate.Rules) != 0 {
			invalidCreate.Rules[0].Verbs = nil
		}
		return invalidCreate
	}
	invalidUpdate := func(created *v3.RoleTemplate) *v3.RoleTemplate {
		invalidUpdateObj := created.DeepCopy()
		if len(invalidUpdateObj.Rules) != 0 {
			invalidUpdateObj.Rules[0].Verbs = nil
		}
		return invalidUpdateObj
	}
	validUpdate := func(created *v3.RoleTemplate) *v3.RoleTemplate {
		validUpdateObj := created.DeepCopy()
		validUpdateObj.Description = "Updated description"
		return validUpdateObj
	}
	validDelete := func() *v3.RoleTemplate {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.RoleTemplate]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}

func (m *IntegrationSuite) TestRoleTemplateNoResources() {
	newObj := func() *v3.RoleTemplate { return &v3.RoleTemplate{} }
	validCreateObj := &v3.RoleTemplate{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-roletemplate-no-resources",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"GET", "WATCH"},
				APIGroups: []string{"v1"},
				Resources: []string{"pods"},
			},
		},
	}
	invalidCreate := func() *v3.RoleTemplate {
		invalidCreate := validCreateObj.DeepCopy()
		if len(invalidCreate.Rules) != 0 {
			invalidCreate.Rules[0].Resources = nil
		}
		return invalidCreate
	}
	validDelete := func() *v3.RoleTemplate {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.RoleTemplate]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}

func (m *IntegrationSuite) TestRoleTemplateNoAPIGroups() {
	newObj := func() *v3.RoleTemplate { return &v3.RoleTemplate{} }
	validCreateObj := &v3.RoleTemplate{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-roletemplate-no-apigroups",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"GET", "WATCH"},
				APIGroups: []string{"v1"},
				Resources: []string{"pods"},
			},
		},
	}
	invalidCreate := func() *v3.RoleTemplate {
		invalidCreate := validCreateObj.DeepCopy()
		if len(invalidCreate.Rules) != 0 {
			invalidCreate.Rules[0].APIGroups = nil
		}
		return invalidCreate
	}
	validDelete := func() *v3.RoleTemplate {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.RoleTemplate]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		validDelete:    validDelete,
	}
	validateEndpoints(m.T(), endPoints, m.clientFactory)
}

// ProjectCreatorDefault=true should not have other than Project context
func (m *IntegrationSuite) TestRoleTemplateWithProjectCreatorDefault() {
	invalidRoleTemplate := &v3.RoleTemplate{
		ObjectMeta: v1.ObjectMeta{
			Name: "test-roletemplate-invalid-context",
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"GET", "WATCH"},
				APIGroups: []string{"v1"},
				Resources: []string{"pods"},
			},
		},
		Context:               "cluster",
		ProjectCreatorDefault: true,
	}
	gvk, err := m.clientFactory.GVKForObject(invalidRoleTemplate)
	m.Require().NoError(err, "Failed to get gvk")
	client, err := m.clientFactory.ForKind(gvk)
	m.Require().NoError(err, "Failed to create client")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	err = client.Create(ctx, invalidRoleTemplate.GetNamespace(), invalidRoleTemplate, nil, v1.CreateOptions{})
	m.Assert().NotNil(err)
	m.Assert().Contains(err.Error(), "RoleTemplate context must be Project when projectCreatorDefault=true")
}
