package integration_test

import (
	"context"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (m *IntegrationSuite) TestGlobalRoleBinding() {
	const grName = "grb-testgr"
	newObj := func() *v3.GlobalRoleBinding { return &v3.GlobalRoleBinding{} }
	validCreateObj := &v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-globalrolebinding",
		},
		UserName:       testUser,
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
		ObjectMeta: metav1.ObjectMeta{
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

func (m *IntegrationSuite) TestMutateGlobalRoleBinding() {
	gvk := schema.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "GlobalRoleBinding"}
	grbClient, err := m.clientFactory.ForKind(gvk)
	m.Require().NoError(err)
	grClient, err := m.clientFactory.ForKind(schema.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "GlobalRole"})
	m.Require().NoError(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	gr := &v3.GlobalRole{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-gr-",
		},
	}
	err = grClient.Create(ctx, "", gr, gr, metav1.CreateOptions{})
	m.Require().NoError(err)
	defer func() {
		_ = grClient.Delete(ctx, "", gr.Name, metav1.DeleteOptions{})
	}()
	validCreateObj := &v3.GlobalRoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-gr-",
		},
		UserName:       testUser,
		GlobalRoleName: gr.Name,
	}
	result := &v3.GlobalRoleBinding{}
	err = grbClient.Create(ctx, validCreateObj.Namespace, validCreateObj, result, metav1.CreateOptions{})
	m.Require().NoError(err)
	var found bool
	for _, ref := range result.OwnerReferences {
		if ref.APIVersion == gr.APIVersion &&
			ref.Kind == gr.Kind &&
			ref.Name == gr.Name &&
			ref.UID == gr.UID {
			found = true
		}
	}
	m.Require().Truef(found, "expected owner reference was not added to GlobalRoleBinding OwnerRef=%+v", result.OwnerReferences)
	err = grbClient.Delete(ctx, result.Namespace, result.Name, metav1.DeleteOptions{})
	m.Require().NoError(err)
	err = grClient.Delete(ctx, gr.Namespace, gr.Name, metav1.DeleteOptions{})
	m.Require().NoError(err)
}
