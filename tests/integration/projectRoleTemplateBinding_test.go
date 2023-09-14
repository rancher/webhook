package integration_test

import (
	"fmt"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (m *IntegrationSuite) TestProjectRoleTemplateBinding() {
	const rtName = "rt-testprtb"
	newObj := func() *v3.ProjectRoleTemplateBinding { return &v3.ProjectRoleTemplateBinding{} }
	validCreateObj := &v3.ProjectRoleTemplateBinding{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-projectroletemplatebinding",
			Namespace: testNamespace,
		},
		UserName:         "bruce-wayne",
		RoleTemplateName: rtName,
		ProjectName:      fmt.Sprintf("%s:%s", "gotham", testNamespace),
	}
	invalidCreate := func() *v3.ProjectRoleTemplateBinding {
		invalidCreate := validCreateObj.DeepCopy()
		invalidCreate.RoleTemplateName = "foo"
		return invalidCreate
	}
	invalidUpdate := func(created *v3.ProjectRoleTemplateBinding) *v3.ProjectRoleTemplateBinding {
		invalidUpdateObj := created.DeepCopy()
		invalidUpdateObj.UserName = "daemon"
		return invalidUpdateObj
	}
	validUpdate := func(created *v3.ProjectRoleTemplateBinding) *v3.ProjectRoleTemplateBinding {
		validUpdateObj := created.DeepCopy()
		validUpdateObj.UserPrincipalName = "local://"
		return validUpdateObj
	}
	validDelete := func() *v3.ProjectRoleTemplateBinding {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.ProjectRoleTemplateBinding]{
		invalidCreate:  invalidCreate,
		newObj:         newObj,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
	}

	testRT := &v3.RoleTemplate{
		ObjectMeta: v1.ObjectMeta{
			Name: rtName,
		},
		Rules: []rbacv1.PolicyRule{
			{
				Verbs:     []string{"GET", "WATCH"},
				APIGroups: []string{"v1"},
				Resources: []string{"pods"},
			},
		},
		Context: "project",
	}
	m.createObj(testRT, schema.GroupVersionKind{})
	validateEndpoints(m.T(), endPoints, m.clientFactory)
	m.deleteObj(testRT, schema.GroupVersionKind{})
}
