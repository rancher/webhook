package integration_test

import (
	"context"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/sirupsen/logrus"
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
	// Wait 2 minutes for the object to be created (should be more than ample time)
	timeout := int64(5 * time.Minute)
	listOptions := metav1.ListOptions{
		Watch:          true,
		TimeoutSeconds: &timeout,
	}
	watcher, err := client.Watch(ctx, validCreateObj.Namespace, listOptions)
	m.NoError(err, "Error returned trying to watch the clusterProxyConfig")
	if watcher != nil {
		// If `m.NoError` fails, code still keeps running and we have a nil watcher
		defer watcher.Stop()
		for {
			receivedEvent, ok := <-watcher.ResultChan()
			if !ok {
				logrus.Infof("Got a non-ok event from the watcher; breaking")
				break
			}
			if receivedEvent.Object.GetObjectKind().GroupVersionKind().Kind == "ClusterProxyConfig" {
				err = client.Get(ctx, validCreateObj.Namespace, cpcName, result, metav1.GetOptions{})
				if err == nil {
					break
				}
				logrus.Infof("client.Get(...) => err %s", err)
				break
			}
		}
	}

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
