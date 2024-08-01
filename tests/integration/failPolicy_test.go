package integration_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/rancher/lasso/pkg/client"
	v3 "github.com/rancher/rancher/pkg/apis/cluster.cattle.io/v3"
	mgmtv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	provisioningv1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/wrangler/v2/pkg/gvk"
	"github.com/rancher/wrangler/v2/pkg/kubeconfig"
	"github.com/rancher/wrangler/v2/pkg/schemes"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type FailurePolicySuite struct {
	suite.Suite
	clientFactory client.SharedClientFactory
}

// TestFailurePolicyTest should be run only when the webhook is not running.
func TestFailurePolicyTest(t *testing.T) {
	suite.Run(t, new(FailurePolicySuite))
}

func (m *FailurePolicySuite) SetupSuite() {
	logrus.SetLevel(logrus.DebugLevel)
	kubeconfigPath := os.Getenv("KUBECONFIG")
	logrus.Infof("Setting up test with KUBECONFIG=%s", kubeconfigPath)
	restCfg, err := kubeconfig.GetNonInteractiveClientConfig(kubeconfigPath).ClientConfig()
	m.Require().NoError(err, "Failed to clientFactory config")
	m.clientFactory, err = client.NewSharedClientFactoryForConfig(restCfg)
	m.Require().NoError(err, "Failed to create clientFactory Interface")

	schemes.Register(v3.AddToScheme)
	schemes.Register(provisioningv1.AddToScheme)
	schemes.Register(corev1.AddToScheme)
}
func (m *FailurePolicySuite) SetupTest() {
	m.checkWebhookIsDown()
}

func (m *FailurePolicySuite) checkWebhookIsDown() {
	podGVK := schema.GroupVersionKind{
		Group:   "",
		Version: "v1",
		Kind:    "Pod",
	}

	podClient, err := m.clientFactory.ForKind(podGVK)
	m.Require().NoError(err, "Failed to create client")
	listOpts := v1.ListOptions{
		LabelSelector: "app=rancher-webhook",
	}
	pods := corev1.PodList{}
	podClient.List(context.Background(), "cattle-system", &pods, listOpts)
	m.Require().Equal(0, len(pods.Items), "Test can not run while rancher-webhook pods are still running")
}

func (m *FailurePolicySuite) TestNamespaceFail() {
	const name = "test-namespace"
	validCreateObj := &corev1.Namespace{
		ObjectMeta: v1.ObjectMeta{
			Name: name,
		},
	}

	objGVK, err := gvk.Get(validCreateObj)
	m.Require().NoError(err, "failed to get GVK")

	client, err := m.clientFactory.ForKind(objGVK)
	m.Require().NoError(err, "Failed to create client")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	err = client.Create(ctx, "", validCreateObj, nil, v1.CreateOptions{})
	m.Require().True(errors.IsInternalError(err), "Webhook should fail with service unavailable when the webhook is down instead we received :%v", err)

	// Attempt to clean up the namespace if the create went through.
	defer client.Delete(ctx, "", name, v1.DeleteOptions{})

	validCreateObj.Name = "default"
	err = client.Update(ctx, "", validCreateObj, nil, v1.UpdateOptions{})
	m.Require().True(errors.IsInternalError(err), "Webhook should fail with service unavailable when the webhook is down instead we received :%v", err)

	validCreateObj.Name = "kube-system"
	err = client.Create(ctx, "", validCreateObj, nil, v1.CreateOptions{})
	m.Require().True(errors.IsAlreadyExists(err), "Webhook should fail to create kube-system with an already exist error instead we received :%v", err)

	err = client.Update(ctx, "", validCreateObj, nil, v1.UpdateOptions{})
	m.Require().True(errors.IsInternalError(err), "Webhook should fail to update kube-system namespace with service unavailable when the webhook is down instead we received :%v", err)
}

func (m *FailurePolicySuite) TestSettingSucceed() {
	const name = "new-setting"
	createObj := &mgmtv3.Setting{
		ObjectMeta: v1.ObjectMeta{
			Name: name,
		},
	}
	objGVK, err := gvk.Get(createObj)
	m.Require().NoError(err, "failed to get GVK")

	client, err := m.clientFactory.ForKind(objGVK)
	m.Require().NoError(err, "Failed to create client")

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*2)
	defer cancel()
	err = client.Create(ctx, "", createObj, nil, v1.CreateOptions{})
	m.Require().NoError(err)

	// Attempt to clean up the setting if the create went through.
	defer client.Delete(ctx, "", name, v1.DeleteOptions{})

	updateObj := &mgmtv3.Setting{}
	err = client.Get(ctx, "", name, updateObj, v1.GetOptions{})
	m.Require().NoError(err)
	updateObj.Value = "new-value"

	err = client.Update(ctx, "", updateObj, updateObj, v1.UpdateOptions{})
	m.Require().NoError(err)
}
