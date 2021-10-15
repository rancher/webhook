package server

import (
	"context"
	"crypto/x509"
	"github.com/gorilla/mux"
	"github.com/rancher/dynamiclistener"
	"github.com/rancher/dynamiclistener/server"
	"github.com/rancher/webhook/pkg/capi"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/sirupsen/logrus"
	v1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"net/http"
	"os"
	"time"
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

func deleteTLSCertOnFailedVerification(clients *clients.Clients, secret *corev1.Secret)  {
	cert := x509.Certificate{
		Raw: secret.Data[corev1.TLSCertKey],
	}
	if _, err := cert.Verify(x509.VerifyOptions{}); err != nil {
		logrus.Errorf("[handleExpiredCerts] certificate verification failed: %v", err)

		if err := clients.Core.Secret().Delete(secret.Namespace, secret.Name, &metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			logrus.Errorf("[handleExpiredCerts] encountered error while attempting to delete %s in namespace %s: %v", secret.Name, secret.Namespace, err)
		} else {
			// Only exit to trigger pod restart upon successful TLS secret deletion or if the secret does not exist.
			logrus.Info("[handleExpiredCerts] exiting with exit code 0 in order to trigger pod restart ")
			os.Exit(0)
		}
	}
}

func ListenAndServe(ctx context.Context, cfg *rest.Config, capiEnabled, mcmEnabled bool) error {
	clients, err := clients.New(ctx, cfg, mcmEnabled)
	if err != nil {
		return err
	}

	secret, err := clients.Core.Secret().Get(namespace, certName, metav1.GetOptions{})
	if err == nil {
		deleteTLSCertOnFailedVerification(clients, secret)
	} else if !apierrors.IsNotFound(err) {
		logrus.Errorf("[ListenAndServe] could not get secret %s in namespace %s: %v", certName, namespace, err)
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
