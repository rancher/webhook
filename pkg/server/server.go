package server

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/rancher/dynamiclistener"
	"github.com/rancher/dynamiclistener/server"
	"github.com/rancher/webhook/pkg/capi"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const (
	serviceName = "rancher-webhook"
	namespace   = "cattle-system"
	tlsName     = "rancher-webhook.cattle-system.svc"
	certName    = "cattle-webhook-tls"
	caName      = "cattle-webhook-ca"
)

var (
	// These have to remain as vars since we need the address below
	port                        = int32(443)
	validationPath              = "/v1/webhook/validation"
	mutationPath                = "/v1/webhook/mutation"
	clusterScope                = v1.ClusterScope
	namespaceScope              = v1.NamespacedScope
	failPolicyFail              = v1.Fail
	failPolicyIgnore            = v1.Ignore
	sideEffectClassNone         = v1.SideEffectClassNone
	sideEffectClassNoneOnDryRun = v1.SideEffectClassNoneOnDryRun
)

func ListenAndServe(ctx context.Context, cfg *rest.Config, capiEnabled, mcmEnabled bool) error {
	clients, err := clients.New(ctx, cfg, mcmEnabled)
	if err != nil {
		return err
	}

	if err := setCertificateExpirationDays(); err != nil {
		// If this error occurs, certificate creation will still work. However, our override will likely not have worked.
		// This will not affect functionality of the webhook, but users may have to perform the workaround:
		// https://github.com/rancher/docs/issues/3637
		logrus.Infof("[ListenAndServe] could not set certificate expiration days via environment variable: %v", err)
	}

	validation, err := Validation(clients)
	if err != nil {
		return err
	}

	mutation, err := Mutation(clients)
	if err != nil {
		return err
	}

	var (
		capiStart func(context.Context) error
	)
	if capiEnabled {
		capiStart, err = capi.Register(ctx, clients)
		if err != nil {
			return err
		}
	}

	router := mux.NewRouter()
	router.Handle(validationPath, validation)
	router.Handle(mutationPath, mutation)
	if err := listenAndServe(ctx, clients, router); err != nil {
		return err
	}

	if err := clients.Start(ctx); err != nil {
		return err
	}

	if capiStart != nil {
		if err := capiStart(ctx); err != nil {
			return err
		}
	}

	return nil
}

// By default, dynamiclistener sets newly signed certificates to expire after 365 days. Since the
// self-signed certificate for webhook does not need to be rotated, we increase expiration time
// beyond relevance. In this case, that's 3650 days (10 years).
func setCertificateExpirationDays() error {
	certExpirationDaysKey := "CATTLE_NEW_SIGNED_CERT_EXPIRATION_DAYS"
	if os.Getenv(certExpirationDaysKey) == "" {
		return os.Setenv(certExpirationDaysKey, "3650")
	}
	return nil
}

func listenAndServe(ctx context.Context, clients *clients.Clients, handler http.Handler) (rErr error) {
	apply := clients.Apply.WithDynamicLookup()

	clients.Core.Secret().OnChange(ctx, "secrets", func(key string, secret *corev1.Secret) (*corev1.Secret, error) {
		if secret == nil || secret.Name != caName || secret.Namespace != namespace || len(secret.Data[corev1.TLSCertKey]) == 0 {
			return nil, nil
		}

		logrus.Info("Sleeping for 15 seconds then applying webhook config")
		// Sleep here to make sure server is listening and all caches are primed
		time.Sleep(15 * time.Second)

		rancherAuthRules := rancherAuthBaseRules
		if clients.MultiClusterManagement { // register additional rbac rules if mcm is enabled
			rancherAuthRules = append(rancherAuthRules, rancherAuthMCMRules...)
		}

		validationClientConfig := v1.WebhookClientConfig{
			Service: &v1.ServiceReference{
				Namespace: namespace,
				Name:      serviceName,
				Path:      &validationPath,
				Port:      &port,
			},
			CABundle: secret.Data[corev1.TLSCertKey],
		}

		mutationClientConfig := v1.WebhookClientConfig{
			Service: &v1.ServiceReference{
				Namespace: namespace,
				Name:      serviceName,
				Path:      &mutationPath,
				Port:      &port,
			},
			CABundle: secret.Data[corev1.TLSCertKey],
		}

		return secret, apply.WithOwner(secret).ApplyObjects(&v1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "rancher.cattle.io",
			},
			Webhooks: []v1.ValidatingWebhook{
				{
					Name:                    "rancher.cattle.io",
					ClientConfig:            validationClientConfig,
					Rules:                   rancherRules,
					FailurePolicy:           &failPolicyIgnore,
					SideEffects:             &sideEffectClassNone,
					AdmissionReviewVersions: []string{"v1", "v1beta1"},
				},
				{
					Name:                    "rancherauth.cattle.io",
					ClientConfig:            validationClientConfig,
					Rules:                   rancherAuthRules,
					FailurePolicy:           &failPolicyFail,
					SideEffects:             &sideEffectClassNone,
					AdmissionReviewVersions: []string{"v1", "v1beta1"},
				},
			},
		}, &v1.MutatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "rancher.cattle.io",
			},
			Webhooks: []v1.MutatingWebhook{
				{
					Name:                    "rancherfleet.cattle.io",
					ClientConfig:            mutationClientConfig,
					Rules:                   fleetMutationRules,
					FailurePolicy:           &failPolicyFail,
					SideEffects:             &sideEffectClassNoneOnDryRun,
					AdmissionReviewVersions: []string{"v1", "v1beta1"},
				},
				{
					Name:                    "rancher.cattle.io",
					ClientConfig:            mutationClientConfig,
					Rules:                   rancherMutationRules,
					FailurePolicy:           &failPolicyFail,
					SideEffects:             &sideEffectClassNoneOnDryRun,
					AdmissionReviewVersions: []string{"v1", "v1beta1"},
				},
			},
		})
	})

	defer func() {
		if rErr != nil {
			return
		}
		rErr = clients.Start(ctx)
	}()

	return server.ListenAndServe(ctx, 9443, 0, handler, &server.ListenOpts{
		Secrets:       clients.Core.Secret(),
		CertNamespace: namespace,
		CertName:      certName,
		CAName:        caName,
		TLSListenerConfig: dynamiclistener.Config{
			SANs: []string{
				tlsName,
			},
			FilterCN: dynamiclistener.OnlyAllow(tlsName),
		},
	})
}
