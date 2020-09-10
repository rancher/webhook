package admission

import (
	"context"
	"net/http"

	"github.com/rancher/dynamiclistener"
	"github.com/rancher/dynamiclistener/server"
	"github.com/rancher/wrangler/pkg/apply"
	"github.com/rancher/wrangler/pkg/generated/controllers/core"
	"github.com/rancher/wrangler/pkg/schemes"
	v1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	namespace    = "cattle-system"
	tlsName      = "rancher-webhook.cattle-system.svc"
	certName     = "cattle-webhook-tls"
	caName       = "cattle-webhook-ca"
	port         = int32(9443)
	path         = "/v1/webhook/validation"
	clusterScope = v1.ClusterScope
	failPolicy   = v1.Fail
	sideEffect   = v1.SideEffectClassNone
)

func ListenAndServe(ctx context.Context, cfg *rest.Config) error {
	if err := schemes.Register(v1.AddToScheme); err != nil {
		return err
	}

	k8s, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return err
	}

	handler := Validation(k8s.AuthorizationV1().SubjectAccessReviews())

	return listenAndServe(ctx, cfg, handler)
}

func listenAndServe(ctx context.Context, cfg *rest.Config, handler http.Handler) (rErr error) {
	apply, err := apply.NewForConfig(cfg)
	if err != nil {
		return err
	}

	apply = apply.WithDynamicLookup()

	coreControllers, err := core.NewFactoryFromConfigWithNamespace(cfg, namespace)
	if err != nil {
		return err
	}

	coreControllers.Core().V1().Secret().OnChange(ctx, "secrets", func(key string, secret *corev1.Secret) (*corev1.Secret, error) {
		if secret == nil || secret.Name != caName || len(secret.Data[corev1.TLSCertKey]) == 0 {
			return nil, nil
		}

		return secret, apply.WithOwner(secret).ApplyObjects(&v1.ValidatingWebhookConfiguration{
			ObjectMeta: metav1.ObjectMeta{
				Name: "rancher.cattle.io",
			},
			Webhooks: []v1.ValidatingWebhook{
				{
					Name: "rancher.cattle.io",
					ClientConfig: v1.WebhookClientConfig{
						Service: &v1.ServiceReference{
							Namespace: namespace,
							Name:      "rancher-webhook",
							Path:      &path,
							Port:      &port,
						},
						CABundle: secret.Data[corev1.TLSCertKey],
					},
					Rules: []v1.RuleWithOperations{
						{
							Operations: []v1.OperationType{
								v1.Create,
								v1.Update,
							},
							Rule: v1.Rule{
								APIGroups:   []string{"management.cattle.io"},
								APIVersions: []string{"v3"},
								Resources:   []string{"clusters"},
								Scope:       &clusterScope,
							},
						},
					},
					FailurePolicy:           &failPolicy,
					SideEffects:             &sideEffect,
					AdmissionReviewVersions: []string{"v1"},
				},
			},
		})
	})

	defer func() {
		if rErr != nil {
			return
		}
		rErr = coreControllers.Start(ctx, 1)
	}()

	return server.ListenAndServe(ctx, 9443, 0, handler, &server.ListenOpts{
		Secrets:       coreControllers.Core().V1().Secret(),
		CertNamespace: namespace,
		CertName:      certName,
		CAName:        caName,
		TLSListenerConfig: dynamiclistener.Config{
			SANs: []string{
				"rancher-webhook",
			},
			CloseConnOnCertChange: false,
			FilterCN:              only(tlsName),
		},
	})
}

func only(str string) func(...string) []string {
	return func(s2 ...string) []string {
		for _, s := range s2 {
			if s == str {
				return []string{s}
			}
		}
		return nil
	}
}
