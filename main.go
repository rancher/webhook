//go:generate go run pkg/codegen/cleanup/main.go
//go:generate go run pkg/codegen/main.go
package main

import (
	"context"
	"os"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/wrangler/pkg/kubeconfig"
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

	ctx := signals.SetupSignalHandler(context.Background())
	if err := admission.ListenAndServe(ctx, cfg); err != nil {
		return err
	}

	<-ctx.Done()
	return nil
}
