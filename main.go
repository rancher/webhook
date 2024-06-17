//go:generate go run pkg/codegen/cleanup/main.go
//go:generate go run ./pkg/codegen
package main

import (
	"fmt"
	"os"

	"github.com/rancher/webhook/pkg/server"
	_ "github.com/rancher/wrangler/v3/pkg/generated/controllers/admissionregistration.k8s.io"
	"github.com/rancher/wrangler/v3/pkg/k8scheck"
	"github.com/rancher/wrangler/v3/pkg/kubeconfig"
	"github.com/rancher/wrangler/v3/pkg/ratelimit"
	"github.com/rancher/wrangler/v3/pkg/signals"
	"github.com/sirupsen/logrus"
)

var (
	Version   = "dev"
	GitCommit = "HEAD"
)

func main() {
	if err := run(); err != nil {
		logrus.Fatal(err)
	}
}

func run() error {
	if os.Getenv("CATTLE_DEBUG") == "true" || os.Getenv("RANCHER_DEBUG") == "true" {
		logrus.SetLevel(logrus.DebugLevel)
	}
	if os.Getenv("CATTLE_TRACE") == "true" {
		logrus.SetLevel(logrus.TraceLevel)
	}

	logrus.Infof("Rancher-webhook version %s is starting", fmt.Sprintf("%s (%s)", Version, GitCommit))

	cfg, err := kubeconfig.GetNonInteractiveClientConfig(os.Getenv("KUBECONFIG")).ClientConfig()
	if err != nil {
		return err
	}

	cfg.RateLimiter = ratelimit.None

	ctx := signals.SetupSignalContext()

	err = k8scheck.Wait(ctx, *cfg)
	if err != nil {
		return err
	}

	if err := server.ListenAndServe(ctx, cfg, os.Getenv("ENABLE_MCM") != "false"); err != nil {
		return err
	}

	<-ctx.Done()
	return nil
}
