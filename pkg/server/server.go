// Package server is used to create and run the webhook server
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/rancher/webhook/pkg/health"
	"github.com/sirupsen/logrus"
	"k8s.io/client-go/rest"
)

const (
	validationPath          = "/v1/webhook/validation"
	mutationPath            = "/v1/webhook/mutation"
	webhookHTTPPort         = 0 // value of 0 indicates we do not want to use http.
	defaultWebhookHTTPSPort = 9443
	webhookPortEnvKey       = "CATTLE_PORT"
	webhookCertDirEnvKey    = "CATTLE_WEBHOOK_CERT_DIR"
	defaultCertDir          = "/tmp/k8s-webhook-server/serving-certs"
	allowedCNsEnv           = "ALLOWED_CNS"
)

var caFile = filepath.Join(os.TempDir(), "k8s-webhook-server", "client-ca", "ca.crt")

// tlsOpt configures the TLS settings shared by the serving listener.
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

func listenAndServe(ctx context.Context, clients *clients.Clients, validators []admission.ValidatingAdmissionHandler, mutators []admission.MutatingAdmissionHandler) (rErr error) {
	router := http.NewServeMux()
	errChecker := health.NewErrorChecker("config-applied")
	health.RegisterHealthCheckers(router, errChecker)

	logrus.Debug("Creating Webhook routes")
	for _, webhook := range validators {
		path := admission.Path(validationPath, webhook)
		router.HandleFunc(path, admission.NewValidatingHandlerFunc(webhook))
		logrus.Debugf("creating route: %s", path)
	}
	for _, webhook := range mutators {
		path := admission.Path(mutationPath, webhook)
		router.HandleFunc(path, admission.NewMutatingHandlerFunc(webhook))
		logrus.Debugf("creating route: %s", path)
	}

	routerHandler := certAuth()(router)

	defer func() {
		if rErr != nil {
			return
		}
		rErr = clients.Start(ctx)
	}()

	webhookHTTPSPort := defaultWebhookHTTPSPort
	if portStr := os.Getenv(webhookPortEnvKey); portStr != "" {
		var err error
		webhookHTTPSPort, err = strconv.Atoi(portStr)
		if err != nil {
			return fmt.Errorf("failed to decode webhook port value '%s': %w", portStr, err)
		}
	}

	certDir := defaultCertDir
	if dir := os.Getenv(webhookCertDirEnvKey); dir != "" {
		certDir = dir
	}
	certPath := filepath.Join(certDir, "tls.crt")
	keyPath := filepath.Join(certDir, "tls.key")

	tlsConfig := &tls.Config{
		GetCertificate: certReloader(certPath, keyPath),
	}
	tlsOpt(tlsConfig)

	server := &http.Server{
		Addr:      fmt.Sprintf(":%d", webhookHTTPSPort),
		Handler:   routerHandler,
		TLSConfig: tlsConfig,
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithCancel(context.Background())
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			logrus.Warnf("webhook server shutdown returned error: %v", err)
		}
	}()

	logrus.Infof("listening on :%d serving certs from %s", webhookHTTPSPort, certDir)
	// Pre-load once so a missing/unreadable cert surfaces at startup rather than per-request.
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return fmt.Errorf("failed to load serving cert from %s: %w", certDir, err)
	}
	if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("webhook server stopped: %w", err)
	}
	return nil
}

// certReloader returns a GetCertificate that re-reads the cert files on every TLS
// handshake. This is intentionally re-read each time so that needacert can rotate
// the underlying secret (kubelet refreshes the projected files on its own cycle)
// without needing a webhook pod restart.
func certReloader(certPath, keyPath string) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, err
		}
		return &cert, nil
	}
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
