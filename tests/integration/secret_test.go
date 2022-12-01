package integration_test

import (
	"context"
	"time"

	"github.com/rancher/webhook/pkg/auth"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func (m *IntegrationSuite) TestSecret() {
	objGVK := schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Secret",
	}
	validCreateObj := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster",
			Namespace: testNamespace,
		},
		Type: v1.SecretType("provisioning.cattle.io/cloud-credential"),
	}
	client, err := m.clientFactory.ForKind(objGVK)
	m.Require().NoError(err, "Failed to create client")
	result := &v1.Secret{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	err = client.Create(ctx, validCreateObj.Namespace, validCreateObj, result, metav1.CreateOptions{})
	m.NoError(err, "Error returned during the creation of a valid Object")
	m.Contains(result.Annotations, auth.CreatorIDAnn)
	err = client.Delete(ctx, validCreateObj.Namespace, validCreateObj.Name, metav1.DeleteOptions{})
	m.NoError(err, "Error returned during the deletion of a valid Object")
}
