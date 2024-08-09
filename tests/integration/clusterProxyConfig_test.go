package integration_test

import (
	"context"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// TestClusterProxyConfig tests that the webhook correctly limits the number of
// ClusterProxyConfig objects that can exist in a single namespace.
func (m *IntegrationSuite) TestClusterProxyConfig() {
	objGVK := schema.GroupVersionKind{
		Group:   "management.cattle.io",
		Version: "v3",
		Kind:    "ClusterProxyConfig",
	}
	cpcName := "testclusterproxyconfig"
	validCreateObj := getObjectToCreate(cpcName)
	client, err := m.clientFactory.ForKind(objGVK)
	m.Require().NoError(err, "Failed to create client")
	result := &v3.ClusterProxyConfig{}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	// Creating the first CPC should succeed
	err = client.Create(ctx, validCreateObj.Namespace, validCreateObj, result, metav1.CreateOptions{})
	m.NoError(err, "Error returned during the creation of a valid clusterProxyConfig")

	// Verify the API knows about the first object before we try to create a second one.
	// Wait 5 minutes for the object to be created (should be more than ample time)
	timeout := int64(5 * time.Minute)
	listOptions := metav1.ListOptions{
		Watch:          true,
		TimeoutSeconds: &timeout,
	}
	watcher, err := client.Watch(ctx, validCreateObj.Namespace, listOptions)
	m.Require().NoError(err, "Error returned trying to watch the clusterProxyConfig")
	defer watcher.Stop()

	receivedEvent, ok := <-watcher.ResultChan()
	m.Require().True(ok, "The CPC watcher closed before it sent any notifications")
	m.Require().EqualValues(receivedEvent.Object.GetObjectKind().GroupVersionKind().Kind, "ClusterProxyConfig")

	secondCPC := getObjectToCreate("anotherclusterproxyconfig")
	// Attempting to create another CPC in the same namespace should fail
	err = client.Create(ctx, validCreateObj.Namespace, secondCPC, result, metav1.CreateOptions{})
	m.Error(err, "Error was not returned when attempting to create a second clusterProxyConfig")
	err = client.Delete(ctx, validCreateObj.Namespace, validCreateObj.Name, metav1.DeleteOptions{})
	m.NoError(err, "Error returned during the deletion of a clusterProxyConfig")
}

func getObjectToCreate(name string) *v3.ClusterProxyConfig {
	return &v3.ClusterProxyConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNamespace,
		},
		Enabled: true,
	}
}
