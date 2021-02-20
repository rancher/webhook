package capi

import (
	"context"
	"os"

	controllerruntime "github.com/rancher/lasso/controller-runtime"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/rancher/wrangler/pkg/schemes"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	clusterv1alpha3 "sigs.k8s.io/cluster-api/api/v1alpha3"
	clusterv1alpha4 "sigs.k8s.io/cluster-api/api/v1alpha4"
	addonsv1alpha3 "sigs.k8s.io/cluster-api/exp/addons/api/v1alpha3"
	expv1alpha3 "sigs.k8s.io/cluster-api/exp/api/v1alpha3"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func init() {
	_ = clientgoscheme.AddToScheme(schemes.All)
	_ = clusterv1alpha3.AddToScheme(schemes.All)
	_ = clusterv1alpha4.AddToScheme(schemes.All)
	_ = expv1alpha3.AddToScheme(schemes.All)
	_ = addonsv1alpha3.AddToScheme(schemes.All)
	_ = apiextensionsv1.AddToScheme(schemes.All)
}

const (
	tlsCert = "/tmp/k8s-webhook-server/serving-certs/tls.crt"
)

func Register(ctx context.Context, clients *clients.Clients) (func(ctx context.Context) error, error) {
	mgr, err := ctrl.NewManager(clients.RESTConfig, ctrl.Options{
		MetricsBindAddress: "0",
		NewCache: controllerruntime.NewNewCacheFunc(clients.SharedControllerFactory.SharedCacheFactory(),
			clients.Dynamic),
		Scheme: schemes.All,
		ClientDisableCacheFor: []client.Object{
			&corev1.ConfigMap{},
			&corev1.Secret{},
		},
		Port: 8777,
	})
	if err != nil {
		return nil, err
	}

	for _, webhook := range webhooks() {
		if err := webhook.SetupWebhookWithManager(mgr); err != nil {
			return nil, err
		}
	}

	return func(ctx context.Context) error {
		if _, err := os.Stat(tlsCert); os.IsNotExist(err) {
			logrus.Errorf("Failed to file %s, not running capi webhooks", tlsCert)
			return nil
		} else if err != nil {
			return err
		}
		return mgr.Start(ctx)
	}, nil
}

func webhooks() []webhook {
	return []webhook{
		&clusterv1alpha4.Cluster{},
		&clusterv1alpha4.Machine{},
		&clusterv1alpha4.MachineHealthCheck{},
		&clusterv1alpha4.MachineSet{},
		&clusterv1alpha4.MachineDeployment{},
	}
}

type webhook interface {
	SetupWebhookWithManager(mgr ctrl.Manager) error
}
