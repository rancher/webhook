// Package server is used to create and run the webhook server
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rancher/dynamiclistener"
	"github.com/rancher/dynamiclistener/server"
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/rancher/webhook/pkg/health"
	admissionregistration "github.com/rancher/wrangler/v3/pkg/generated/controllers/admissionregistration.k8s.io/v1"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
)

const (
	serviceName             = "rancher-webhook"
	namespace               = "cattle-system"
	tlsName                 = "rancher-webhook.cattle-system.svc"
	certName                = "cattle-webhook-tls"
	caName                  = "cattle-webhook-ca"
	validationPath          = "/v1/webhook/validation"
	mutationPath            = "/v1/webhook/mutation"
	clientPort              = int32(443)
	webhookHTTPPort         = 0 // value of 0 indicates we do not want to use http.
	defaultWebhookHTTPSPort = 9443
	webhookPortEnvKey       = "CATTLE_PORT"
	webhookURLEnvKey        = "CATTLE_WEBHOOK_URL"
	allowedCNsEnv           = "ALLOWED_CNS"
	ignoreTLSHandshakeError = "IGNORE_TLS_HANDSHAKE_ERROR"
)

var caFile = filepath.Join(os.TempDir(), "k8s-webhook-server", "client-ca", "ca.crt")

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
	config.ClientAuth = tls.RequestClientCert
}

// ListenAndServe starts the webhook server.
func ListenAndServe(ctx context.Context, cfg *rest.Config, mcmEnabled bool) error {
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

	if err = listenAndServe(ctx, clients, validators, mutators); err != nil {
		return err
	}

	if err = clients.Start(ctx); err != nil {
		return fmt.Errorf("failed to start client: %w", err)
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
	router.Use(certAuth())

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

	defer func() {
		if rErr != nil {
			return
		}
		rErr = clients.Start(ctx)
	}()

	tlsConfig := &tls.Config{}
	tlsOpt(tlsConfig)
	webhookHTTPSPort := defaultWebhookHTTPSPort
	if portStr := os.Getenv(webhookPortEnvKey); portStr != "" {
		var err error
		webhookHTTPSPort, err = strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("failed to decode webhook port value '%s': %w", portStr, err)
		}
	}
	ignoreTLSHandErrorVal, _ := strconv.ParseBool(os.Getenv(ignoreTLSHandshakeError))
	err := server.ListenAndServe(ctx, webhookHTTPSPort, webhookHTTPPort, router, &server.ListenOpts{
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
		DisplayServerLogs:       true,
		IgnoreTLSHandshakeError: ignoreTLSHandErrorVal,
	})
	if err != nil {
		return fmt.Errorf("failed to start webhook server: %w", err)
	}

	err = createWebhookConfigurations(validators, mutators, clients)
	if err != nil {
		return fmt.Errorf("failed to create webhook configurations: %w", err)
	}

	return nil
}

// createWebhookConfigurations creates the webhook admission configuration.
func createWebhookConfigurations(
	validators []admission.ValidatingAdmissionHandler,
	mutators []admission.MutatingAdmissionHandler,
	clients *clients.Clients,
) error {

	secret, err := clients.Core.Secret().Get(namespace, caName, metav1.GetOptions{})
	if err != nil {
		logrus.Errorf("failed to get secret for webhook configuration: %v", err)
		return err
	}

	validationClientConfig := v1.WebhookClientConfig{
		Service: &v1.ServiceReference{
			Namespace: namespace,
			Name:      serviceName,
			Path:      admission.Ptr(validationPath),
			Port:      admission.Ptr(clientPort),
		},
		CABundle: secret.Data[corev1.TLSCertKey],
	}

	mutationClientConfig := v1.WebhookClientConfig{
		Service: &v1.ServiceReference{
			Namespace: namespace,
			Name:      serviceName,
			Path:      admission.Ptr(mutationPath),
			Port:      admission.Ptr(clientPort),
		},
		CABundle: secret.Data[corev1.TLSCertKey],
	}
	if devURL, ok := os.LookupEnv(webhookURLEnvKey); ok {
		validationURL := devURL + validationPath
		mutationURL := devURL + mutationPath
		validationClientConfig = v1.WebhookClientConfig{
			URL: &validationURL,
		}
		mutationClientConfig = v1.WebhookClientConfig{
			URL: &mutationURL,
		}
	}
	validatingWebhooks := make([]v1.ValidatingWebhook, 0, len(validators))
	for _, webhook := range validators {
		validatingWebhooks = append(validatingWebhooks, webhook.ValidatingWebhook(validationClientConfig)...)
	}
	mutatingWebhooks := make([]v1.MutatingWebhook, 0, len(mutators))
	for _, webhook := range mutators {
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
	// Use clients to get controllers
	err = ensureWebhookConfiguration(
		validatingConfig,
		mutatingConfig,
		clients.Admission.ValidatingWebhookConfiguration(),
		clients.Admission.MutatingWebhookConfiguration(),
	)
	if err != nil {
		logrus.Errorf("Failed to ensure configuration: %s", err.Error())
		return err
	}

	return nil
}

// ensureWebhookConfiguration creates validating and mutating webhook configuration to have the desired webhook.
func ensureWebhookConfiguration(
	validatingConfig *v1.ValidatingWebhookConfiguration,
	mutatingConfig *v1.MutatingWebhookConfiguration,
	validatingController admissionregistration.ValidatingWebhookConfigurationClient,
	mutatingController admissionregistration.MutatingWebhookConfigurationClient,
) error {
	currValidating, err := validatingController.Get(validatingConfig.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = validatingController.Create(validatingConfig)
		if err != nil {
			return fmt.Errorf("failed to create validating configuration: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get validating configuration: %w", err)
	} else {
		currValidating.Webhooks = validatingConfig.Webhooks
		_, err = validatingController.Update(currValidating)
		if err != nil {
			return fmt.Errorf("failed to update validating configuration: %w", err)
		}
	}

	currMutation, err := mutatingController.Get(mutatingConfig.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		_, err = mutatingController.Create(mutatingConfig)
		if err != nil {
			return fmt.Errorf("failed to create mutating configuration: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("failed to get mutating configuration: %w", err)
	} else {
		currMutation.Webhooks = mutatingConfig.Webhooks
		_, err = mutatingController.Update(currMutation)
		if err != nil {
			return fmt.Errorf("failed to update mutating configuration: %w", err)
		}
	}

	return nil
}

// certAuth returns a middleware for cert-based authentication.
// This is done as a middleware instead of using tls.RequireAndVerifyClientCert because an exception
// needs to be made for the unauthenticated /healthz endpoint.
func certAuth() func(next http.Handler) http.Handler {
	opts := getVerifyOptions()
	allowedCNs := getAllowedCNs()
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			logrus.Tracef("running cert check middleware for request %s", r.URL.Path)
			if opts == nil {
				next.ServeHTTP(w, r)
				return
			}
			if r.URL.Path == "/healthz" { // apiserver does not present client cert for health checks
				next.ServeHTTP(w, r)
				return
			}
			if len(r.TLS.PeerCertificates) == 0 {
				logrus.Warn("client did not present certificates")
				http.Error(w, "could not verify client certificates", http.StatusUnauthorized)
				return
			}
			for _, cert := range r.TLS.PeerCertificates[1:] {
				opts.Intermediates.AddCert(cert)
			}
			_, err := r.TLS.PeerCertificates[0].Verify(*opts)
			if err != nil {
				logrus.Warnf("could not verify client certificates: %v", err)
				http.Error(w, "could not verify client certificates", http.StatusUnauthorized)
				return
			}
			if len(allowedCNs) == 0 {
				next.ServeHTTP(w, r)
				return
			}
			requestCN := r.TLS.PeerCertificates[0].Subject.CommonName
			found := false
			for _, allowed := range allowedCNs {
				if allowed == requestCN {
					found = true
					break
				}
			}
			if !found {
				logrus.Warnf("could not find common name %s in allowed list", requestCN)
				http.Error(w, "common name is not allowed", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func getVerifyOptions() *x509.VerifyOptions {
	caCert, err := os.ReadFile(caFile)
	if err != nil {
		logrus.Infof("could not read client CA file at %s, incoming requests will not be authenticated", caFile)
		return nil
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	opts := x509.VerifyOptions{
		Roots:         caCertPool,
		Intermediates: x509.NewCertPool(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	return &opts
}

func getAllowedCNs() []string {
	allowedCNString := os.Getenv(allowedCNsEnv)
	if len(allowedCNString) == 0 {
		return nil
	}
	return strings.Split(allowedCNString, ",")
}
