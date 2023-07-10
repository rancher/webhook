// Package server is used to create and run the webhook server
package server

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"time"

	"github.com/gorilla/mux"
	"github.com/rancher/dynamiclistener"
	"github.com/rancher/dynamiclistener/server"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/capi"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/rancher/webhook/pkg/health"
	admissionregistration "github.com/rancher/wrangler/pkg/generated/controllers/admissionregistration.k8s.io/v1"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const (
	serviceName      = "rancher-webhook"
	namespace        = "cattle-system"
	tlsName          = "rancher-webhook.cattle-system.svc"
	certName         = "cattle-webhook-tls"
	caName           = "cattle-webhook-ca"
	webhookHTTPPort  = 0 // value of 0 indicates we do not want to use http.
	webhookHTTPSPort = 9443
)

var (
	// These strings have to remain as vars since we need the address below.
	validationPath = "/v1/webhook/validation"
	mutationPath   = "/v1/webhook/mutation"
	clientPort     = int32(443)
)

// tlsOpt option function applied to all webhook servers.
var tlsOpt = func(config *tls.Config) {
	config.MinVersion = tls.VersionTLS12
	config.CipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	}
}

// ListenAndServe starts the webhook server.
func ListenAndServe(ctx context.Context, cfg *rest.Config, capiEnabled, mcmEnabled bool) error {
	clients, err := clients.New(ctx, cfg, mcmEnabled)
	if err != nil {
		return fmt.Errorf("failed to create a new client: %w", err)
	}

	if err = setCertificateExpirationDays(); err != nil {
		// If this error occurs, certificate creation will still work. However, our override will likely not have worked.
		// This will not affect functionality of the webhook, but users may have to perform the workaround:
		// https://github.com/rancher/docs/issues/3637
		logrus.Infof("[ListenAndServe] could not set certificate expiration days via environment variable: %v", err)
	}

	validators, err := Validation(clients)
	if err != nil {
		return err
	}

	mutators, err := Mutation(clients)
	if err != nil {
		return err
	}

	var capiStart func(context.Context) error

	if capiEnabled {
		capiStart, err = capi.Register(clients, tlsOpt)
		if err != nil {
			return fmt.Errorf("failed to register capi: %w", err)
		}
	}

	if err = listenAndServe(ctx, clients, validators, mutators); err != nil {
		return err
	}

	if err = clients.Start(ctx); err != nil {
		return fmt.Errorf("failed to start client: %w", err)
	}

	if capiStart != nil {
		if err = capiStart(ctx); err != nil {
			return fmt.Errorf("failed to start capi: %w", err)
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

func listenAndServe(ctx context.Context, clients *clients.Clients, validators []admission.ValidatingAdmissionHandler, mutators []admission.MutatingAdmissionHandler) (rErr error) {
	router := mux.NewRouter()
	errChecker := health.NewErrorChecker("Config Applied")
	health.RegisterHealthCheckers(router, errChecker)

	logrus.Debug("Creating Webhook routes")
	for _, webhook := range validators {
		route := router.HandleFunc(admission.Path(validationPath, webhook), admission.NewValidatingHandlerFunc(webhook))
		path, _ := route.GetPathTemplate()
		logrus.Debugf("creating route: %s", path)
	}
	for _, webhook := range mutators {
		route := router.HandleFunc(admission.Path(mutationPath, webhook), admission.NewMutatingHandlerFunc(webhook))
		path, _ := route.GetPathTemplate()
		logrus.Debugf("creating route: %s", path)
	}

	handler := &secretHandler{
		validators:           validators,
		mutators:             mutators,
		errChecker:           errChecker,
		validatingController: clients.Admission.ValidatingWebhookConfiguration(),
		mutatingController:   clients.Admission.MutatingWebhookConfiguration(),
	}
	clients.Core.Secret().OnChange(ctx, "secrets", handler.sync)

	defer func() {
		if rErr != nil {
			return
		}
		rErr = clients.Start(ctx)
	}()

	tlsConfig := &tls.Config{}
	tlsOpt(tlsConfig)

	return server.ListenAndServe(ctx, webhookHTTPSPort, webhookHTTPPort, router, &server.ListenOpts{
		Secrets:       clients.Core.Secret(),
		CertNamespace: namespace,
		CertName:      certName,
		CAName:        caName,
		TLSListenerConfig: dynamiclistener.Config{
			SANs: []string{
				tlsName,
			},
			FilterCN:  dynamiclistener.OnlyAllow(tlsName),
			TLSConfig: tlsConfig,
		},
	})
}

type secretHandler struct {
	validators           []admission.ValidatingAdmissionHandler
	mutators             []admission.MutatingAdmissionHandler
	errChecker           *health.ErrorChecker
	validatingController admissionregistration.ValidatingWebhookConfigurationClient
	mutatingController   admissionregistration.MutatingWebhookConfigurationClient
}

// sync updates the validating admission configuration whenever the TLS cert changes.
func (s *secretHandler) sync(_ string, secret *corev1.Secret) (*corev1.Secret, error) {
	if secret == nil || secret.Name != caName || secret.Namespace != namespace || len(secret.Data[corev1.TLSCertKey]) == 0 {
		return nil, nil
	}

	logrus.Info("Sleeping for 15 seconds then applying webhook config")
	// Sleep here to make sure server is listening and all caches are primed
	time.Sleep(15 * time.Second)

	validationClientConfig := v1.WebhookClientConfig{
		Service: &v1.ServiceReference{
			Namespace: namespace,
			Name:      serviceName,
			Path:      &validationPath,
			Port:      &clientPort,
		},
		CABundle: secret.Data[corev1.TLSCertKey],
	}

	mutationClientConfig := v1.WebhookClientConfig{
		Service: &v1.ServiceReference{
			Namespace: namespace,
			Name:      serviceName,
			Path:      &mutationPath,
			Port:      &clientPort,
		},
		CABundle: secret.Data[corev1.TLSCertKey],
	}
	if devURL, ok := os.LookupEnv("CATTLE_WEBHOOK_URL"); ok {
		validationURL := devURL + validationPath
		mutationURL := devURL + mutationPath
		validationClientConfig = v1.WebhookClientConfig{
			URL: &validationURL,
		}
		mutationClientConfig = v1.WebhookClientConfig{
			URL: &mutationURL,
		}
	}
	validatingWebhooks := make([]v1.ValidatingWebhook, 0, len(s.validators))
	for _, webhook := range s.validators {
		validatingWebhooks = append(validatingWebhooks, webhook.ValidatingWebhook(validationClientConfig)...)
	}
	mutatingWebhooks := make([]v1.MutatingWebhook, 0, len(s.mutators))
	for _, webhook := range s.mutators {
		mutatingWebhooks = append(mutatingWebhooks, webhook.MutatingWebhook(mutationClientConfig)...)
	}
	validatingConfig := &v1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rancher.cattle.io",
		},
		Webhooks: validatingWebhooks,
	}
	mutatingConfig := &v1.MutatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{
			Name: "rancher.cattle.io",
		},
		Webhooks: mutatingWebhooks,
	}
	err := s.ensureWebhookConfiguration(validatingConfig, mutatingConfig)

	s.errChecker.Store(err)
	return secret, err

}

// ensureWebhookConfiguration creates or updates the current validating and mutating webhook configuration to have the desired webhook.
func (s *secretHandler) ensureWebhookConfiguration(validatingConfig *v1.ValidatingWebhookConfiguration, mutatingConfig *v1.MutatingWebhookConfiguration) error {

	currValidating, err := s.validatingController.Get(validatingConfig.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = s.validatingController.Create(validatingConfig)
		if err != nil {
			return fmt.Errorf("failed to create validating configuration: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get validating configuration: %w", err)
	} else {
		currValidating.Webhooks = validatingConfig.Webhooks
		_, err = s.validatingController.Update(currValidating)
		if err != nil {
			return fmt.Errorf("failed to update validating configuration: %w", err)
		}
	}

	currMutation, err := s.mutatingController.Get(validatingConfig.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = s.mutatingController.Create(currMutation)
		if err != nil {
			return fmt.Errorf("failed to create mutating configuration: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get mutating configuration: %w", err)
	} else {
		currMutation.Webhooks = mutatingConfig.Webhooks
		_, err = s.mutatingController.Update(currMutation)
		if err != nil {
			return fmt.Errorf("failed to update mutating configuration: %w", err)
		}
	}

	return nil
}
