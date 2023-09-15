package integration_test

import (
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (m *IntegrationSuite) TestClusterRoleTemplateBinding() {
	const rtName = "rt-testcrtb"
	newObj := func() *v3.ClusterRoleTemplateBinding { return &v3.ClusterRoleTemplateBinding{} }
	validCreateObj := &v3.ClusterRoleTemplateBinding{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-clusterroletemplatebinding",
			Namespace: testNamespace,
		},
		UserName:         "bruce-wayne",
		RoleTemplateName: rtName,
		ClusterName:      testNamespace,
	}
	invalidCreate := func() *v3.ClusterRoleTemplateBinding {
		invalidCreate := validCreateObj.DeepCopy()
		invalidCreate.RoleTemplateName = "foo"
		return invalidCreate
	}
	invalidUpdate := func(created *v3.ClusterRoleTemplateBinding) *v3.ClusterRoleTemplateBinding {
		invalidUpdateObj := created.DeepCopy()
		invalidUpdateObj.UserName = "daemon"
		return invalidUpdateObj
	}
	validUpdate := func(created *v3.ClusterRoleTemplateBinding) *v3.ClusterRoleTemplateBinding {
		validUpdateObj := created.DeepCopy()
		validUpdateObj.UserPrincipalName = "local://"
		return validUpdateObj
	}
	validDelete := func() *v3.ClusterRoleTemplateBinding {
		return validCreateObj
	}
	endPoints := &endPointObjs[*v3.ClusterRoleTemplateBinding]{
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
		Context: "cluster",
	}
	m.createObj(testRT, schema.GroupVersionKind{})
	validateEndpoints(m.T(), endPoints, m.clientFactory)
	m.deleteObj(testRT, schema.GroupVersionKind{})
}
