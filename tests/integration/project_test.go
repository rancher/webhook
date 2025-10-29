package integration_test

import (
	"context"
	"encoding/json"
	"math/rand"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
)

const (
	clusterName = "local"
	displayName = "p1"
)

func (m *IntegrationSuite) TestValidateProject() {
	client, err := m.clientFactory.ForKind(schema.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "Project"})
	m.Require().NoError(err)
	ctx := context.Background()
	newObj := func() *v3.Project { return &v3.Project{} }
	validCreateObj := &v3.Project{
		ObjectMeta: metav1.ObjectMeta{
			Name:      randomName(),
			Namespace: clusterName,
		},
		Spec: v3.ProjectSpec{
			DisplayName: displayName,
			ClusterName: clusterName,
			ResourceQuota: &v3.ProjectResourceQuota{
				Limit: v3.ResourceQuotaLimit{
					ConfigMaps: "20",
				},
			},
			NamespaceDefaultResourceQuota: &v3.NamespaceResourceQuota{
				Limit: v3.ResourceQuotaLimit{
					ConfigMaps: "10",
				},
			},
		},
	}
	invalidCreate := func() *v3.Project {
		invalidCreateObj := validCreateObj.DeepCopy()
		invalidCreateObj.Spec.NamespaceDefaultResourceQuota.Limit.ConfigMaps = "100"
		return invalidCreateObj
	}
	validUpdate := func(created *v3.Project) *v3.Project {
		validUpdateObj := created.DeepCopy()
		validUpdateObj.Spec.ResourceQuota.Limit.ConfigMaps = "30"
		return validUpdateObj
	}
	invalidUpdate := func(created *v3.Project) *v3.Project {
		// Normally, rancher would update the used limit when more namespaces are created that use up the quota.
		// Here, rancher isn't running so we have to simulate it by updating the used limit directly.
		updateUsedLimitObj := created.DeepCopy()
		updateUsedLimitObj.Spec.ResourceQuota.UsedLimit.ConfigMaps = "20"
		result := &v3.Project{}
		patch, err := createPatch(result, updateUsedLimitObj)
		m.Require().NoError(err)
		err = client.Patch(ctx, updateUsedLimitObj.GetNamespace(), updateUsedLimitObj.GetName(), types.JSONPatchType, patch, result, metav1.PatchOptions{})
		m.Require().NoError(err)
		result.Spec.ResourceQuota.Limit.ConfigMaps = "15"
		return result
	}
	validDelete := func() *v3.Project {
		return validCreateObj
	}
	invalidDelete := func() *v3.Project {
		projects := &v3.ProjectList{}
		opts := metav1.ListOptions{LabelSelector: "authz.management.cattle.io/system-project=true"}
		err = client.List(ctx, "local", projects, opts)
		require.NoError(m.T(), err)
		systemProject := projects.Items[0]
		return &systemProject
	}
	endpoints := &endPointObjs[*v3.Project]{
		newObj:         newObj,
		invalidCreate:  invalidCreate,
		validCreateObj: validCreateObj,
		invalidUpdate:  invalidUpdate,
		validUpdate:    validUpdate,
		validDelete:    validDelete,
		invalidDelete:  invalidDelete,
	}
	validateEndpoints(m.T(), endpoints, m.clientFactory)
}

func (m *IntegrationSuite) TestMutateProject() {
	projectClient, err := m.clientFactory.ForKind(schema.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "Project"})
	m.Require().NoError(err)
	rtClient, err := m.clientFactory.ForKind(schema.GroupVersionKind{Group: "management.cattle.io", Version: "v3", Kind: "RoleTemplate"})
	m.Require().NoError(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	rt := &v3.RoleTemplate{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "test-project-creator-",
		},
		ProjectCreatorDefault: true,
		Context:               "project",
	}
	err = rtClient.Create(ctx, "", rt, rt, metav1.CreateOptions{})
	m.Require().NoError(err)
	defer func() {
		_ = rtClient.Delete(ctx, "", rt.Name, metav1.DeleteOptions{})
	}()
	validCreateObj := &v3.Project{
		ObjectMeta: metav1.ObjectMeta{
			Name:      randomName(),
			Namespace: clusterName,
		},
		Spec: v3.ProjectSpec{
			ClusterName: clusterName,
		},
	}
	result := &v3.Project{}
	err = projectClient.Create(ctx, validCreateObj.Namespace, validCreateObj, result, metav1.CreateOptions{})
	m.Require().NoError(err)
	m.Require().Contains(result.Annotations, "authz.management.cattle.io/creator-role-bindings")
	annos := result.Annotations["authz.management.cattle.io/creator-role-bindings"]
	annosMap := make(map[string]any)
	err = json.Unmarshal([]byte(annos), &annosMap)
	m.Require().NoError(err)
	m.Require().Contains(annosMap, "required")
	m.Require().Contains(annosMap["required"], rt.Name)
	err = projectClient.Delete(ctx, validCreateObj.Namespace, validCreateObj.Name, metav1.DeleteOptions{})
	m.Require().NoError(err)
}

var seededRand = rand.New(rand.NewSource(time.Now().UnixNano()))

func randomName() string {
	const charset = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, 5)
	for i := 0; i < 5; i++ {
		b[i] = charset[seededRand.Intn(len(charset))]
	}
	return "p-test-" + string(b)
}
