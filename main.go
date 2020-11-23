//go:generate go run pkg/codegen/cleanup/main.go
//go:generate go run pkg/codegen/main.go
package main

import (
	"context"
	"os"

	"github.com/rancher/webhook/pkg/server"
	_ "github.com/rancher/wrangler/pkg/generated/controllers/admissionregistration.k8s.io"
	"github.com/rancher/wrangler/pkg/kubeconfig"
	"github.com/rancher/wrangler/pkg/ratelimit"
	"github.com/rancher/wrangler/pkg/signals"
	"github.com/sirupsen/logrus"
)

func main() {
	if err := run(); err != nil {
		logrus.Fatal(err)
	}
}

func run() error {
	cfg, err := kubeconfig.GetNonInteractiveClientConfig(os.Getenv("KUBECONFIG")).ClientConfig()
	if err != nil {
		return err
	}

	cfg.RateLimiter = ratelimit.None

	ctx := signals.SetupSignalHandler(context.Background())
	if err := server.ListenAndServe(ctx, cfg); err != nil {
		return err
	}

	<-ctx.Done()
	return nil
}
