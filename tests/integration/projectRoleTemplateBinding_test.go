package integration_test

import (
	"context"
	"fmt"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (m *IntegrationSuite) TestProjectRoleTemplateBinding() {
	projectClient, err := m.clientFactory.ForKind(schema.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "Project"})
	m.Require().NoError(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	result := &v3.ProjectList{}
	err = projectClient.List(ctx, clusterName, result, v1.ListOptions{})
	var projectName string
	for _, project := range result.Items {
		if project.Spec.DisplayName != "System" {
			projectName = project.Name
		}
	}
	m.Require().NotEmpty(projectName, "could not find a non-system project to put prtbs in")
	m.Require().NoError(err)
	const rtName = "rt-testprtb"
	newObj := func() *v3.ProjectRoleTemplateBinding { return &v3.ProjectRoleTemplateBinding{} }
	validCreateObj := &v3.ProjectRoleTemplateBinding{
		ObjectMeta: v1.ObjectMeta{
			Name:      "test-projectroletemplatebinding",
			Namespace: projectName,
		},
		UserName:         "bruce-wayne",
		RoleTemplateName: rtName,
		ProjectName:      fmt.Sprintf("%s:%s", clusterName, projectName),
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
