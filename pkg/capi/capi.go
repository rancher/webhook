// Package capi is used to run a CAPI webhook server
package capi

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	controllerruntime "github.com/rancher/lasso/controller-runtime"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/rancher/wrangler/pkg/schemes"
	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	clusterv1alpha3 "sigs.k8s.io/cluster-api/api/v1alpha3"
	clusterv1alpha4 "sigs.k8s.io/cluster-api/api/v1alpha4"
	clusterv1beta1 "sigs.k8s.io/cluster-api/api/v1beta1"
	addonsv1alpha3 "sigs.k8s.io/cluster-api/exp/addons/api/v1alpha3"
	addonsv1alpha4 "sigs.k8s.io/cluster-api/exp/addons/api/v1alpha4"
	addonsv1beta1 "sigs.k8s.io/cluster-api/exp/addons/api/v1beta1"
	expv1alpha3 "sigs.k8s.io/cluster-api/exp/api/v1alpha3"
	expv1alpha4 "sigs.k8s.io/cluster-api/exp/api/v1alpha4"
	expv1beta1 "sigs.k8s.io/cluster-api/exp/api/v1beta1"
	"sigs.k8s.io/cluster-api/webhooks"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

func init() {
	_ = clientgoscheme.AddToScheme(schemes.All)
	_ = clusterv1alpha3.AddToScheme(schemes.All)
	_ = clusterv1alpha4.AddToScheme(schemes.All)
	_ = clusterv1beta1.AddToScheme(schemes.All)
	_ = expv1alpha3.AddToScheme(schemes.All)
	_ = expv1alpha4.AddToScheme(schemes.All)
	_ = expv1beta1.AddToScheme(schemes.All)
	_ = addonsv1alpha3.AddToScheme(schemes.All)
	_ = addonsv1alpha4.AddToScheme(schemes.All)
	_ = addonsv1beta1.AddToScheme(schemes.All)
	_ = apiextensionsv1.AddToScheme(schemes.All)
}

const (
	defaultCapiPort = 8777
	capiPortEnvKey  = "CATTLE_CAPI_PORT"
)

var tlsCert = filepath.Join(os.TempDir(), "k8s-webhook-server", "serving-certs", "tls.crt")

// Register registers a new CAPI webhook server and returns a start function.
func Register(clients *clients.Clients, tlsOpts ...func(*tls.Config)) (func(ctx context.Context) error, error) {
	capiPort := defaultCapiPort
	if portStr := os.Getenv(capiPortEnvKey); portStr != "" {
		var err error
		capiPort, err = strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("failed to decode CAPI port value '%s': %w", portStr, err)
		}
	}
	mgr, err := ctrl.NewManager(clients.RESTConfig, ctrl.Options{
		MetricsBindAddress: "0",
		NewCache: controllerruntime.NewNewCacheFunc(clients.SharedControllerFactory.SharedCacheFactory(),
			clients.Dynamic),
		Scheme: schemes.All,
		ClientDisableCacheFor: []client.Object{
			&corev1.ConfigMap{},
			&corev1.Secret{},
		},
		WebhookServer: webhook.NewServer(webhook.Options{
			Port:          capiPort,
			TLSMinVersion: "1.2",
			TLSOpts:       tlsOpts,
		}),
	})

	if err != nil {
		return nil, err
	}

	for _, capiWebhook := range capiWebhooks() {
		if err := capiWebhook.SetupWebhookWithManager(mgr); err != nil {
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

func capiWebhooks() []capiWebhook {
	return []capiWebhook{
		&webhooks.Cluster{},
		&clusterv1beta1.Machine{},
		&clusterv1beta1.MachineHealthCheck{},
		&clusterv1beta1.MachineSet{},
		&clusterv1beta1.MachineDeployment{},
	}
}

type capiWebhook interface {
	SetupWebhookWithManager(mgr ctrl.Manager) error
}
