package integration_test

import (
	"context"
	"os"
	"testing"

	"github.com/rancher/lasso/pkg/client"
	"github.com/rancher/wrangler/v3/pkg/kubeconfig"
	"github.com/rancher/wrangler/v3/pkg/schemes"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/suite"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const (
	testWebhookPort = 443
)

type PortSuite struct {
	suite.Suite
	clientFactory client.SharedClientFactory
}

// TestPortTest should be run only when the webhook is not running.
func TestPortTest(t *testing.T) {
	suite.Run(t, new(PortSuite))
}

func (m *PortSuite) SetupSuite() {
	logrus.SetLevel(logrus.DebugLevel)
	kubeconfigPath := os.Getenv("KUBECONFIG")
	restCfg, err := kubeconfig.GetNonInteractiveClientConfig(kubeconfigPath).ClientConfig()
	m.Require().NoError(err, "Failed to clientFactory config")
	m.clientFactory, err = client.NewSharedClientFactoryForConfig(restCfg)
	m.Require().NoError(err, "Failed to create clientFactory Interface")

	schemes.Register(corev1.AddToScheme)
}

func (m *PortSuite) TestWebhookPortChanged() {
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
	var webhookPod *corev1.Pod
	for _, pod := range pods.Items {
		if pod.Status.Phase == corev1.PodRunning {
			if webhookPod != nil {
				m.Require().FailNow("more then one rancher-webhook pod is running")
			}
			webhookPod = &pod
		}
	}
	if webhookPod == nil {
		m.Require().FailNow("running webhook pod not found")
	}
	m.Require().Equal(corev1.PodRunning, webhookPod.Status.Phase, "Rancher-webhook pod is not running Phase=%s", webhookPod.Status.Phase)
	m.Require().Len(webhookPod.Spec.Containers, 1, "Rancher-webhook pod has the incorrect number of containers")
	m.Require().Len(webhookPod.Spec.Containers[0].Ports, 1, "Rancher-webhook container has the incorrect number of ports")
	havePort := webhookPod.Spec.Containers[0].Ports[0].ContainerPort
	if havePort != testWebhookPort {
		m.Require().FailNowf("expected webhook port not found", "wanted '%d' was not found instead have '%d'", testWebhookPort, havePort)
	}
}
