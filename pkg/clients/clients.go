package clients

import (
	"context"
	"time"

	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io"
	managementv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/generated/controllers/provisioning.cattle.io"
	provv1 "github.com/rancher/webhook/pkg/generated/controllers/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/generated/controllers/rke.cattle.io"
	rkev1 "github.com/rancher/webhook/pkg/generated/controllers/rke.cattle.io/v1"
	"github.com/rancher/wrangler/v3/pkg/clients"
	"github.com/rancher/wrangler/v3/pkg/schemes"
	v1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const (
	// Ten seconds reduces repeated SAR calls while keeping the delay after
	// permission grants or revocations short.
	sarAllowCacheTTL = 10 * time.Second
	sarDenyCacheTTL  = 10 * time.Second
)

type Clients struct {
	clients.Clients

	Authorizer             authorizer.Authorizer
	MultiClusterManagement bool
	Management             managementv3.Interface
	Provisioning           provv1.Interface
	RKE                    rkev1.Interface
	RoleTemplateResolver   *auth.RoleTemplateResolver
	GlobalRoleResolver     *auth.GlobalRoleResolver
	DefaultResolver        validation.AuthorizationRuleResolver
}

// Options controls how New builds the webhook Clients.
type Options struct {
	MCMEnabled bool
	// StartCache starts the management informer factory's cache. It must be
	// true for a running webhook. It is only set to false by codegen tooling
	// that needs the handler wiring (Validation/Mutation) without a live
	// cluster to talk to.
	StartCache bool
}

func New(ctx context.Context, rest *rest.Config, mcmEnabled bool) (*Clients, error) {
	return NewWithOptions(ctx, rest, &Options{
		MCMEnabled: mcmEnabled,
		StartCache: true,
	})
}

func NewWithOptions(ctx context.Context, rest *rest.Config, opts *Options) (*Clients, error) {
	clients, err := clients.NewFromConfig(rest, nil)
	if err != nil {
		return nil, err
	}

	// Create one authorizer to share cached SAR decisions across validators and admission requests.
	sarAuthorizer, err := newSARAuthorizer(clients.K8s.AuthorizationV1())
	if err != nil {
		return nil, err
	}

	if err := schemes.Register(v1.AddToScheme); err != nil {
		return nil, err
	}

	mgmt, err := management.NewFactoryFromConfigWithOptions(rest, clients.FactoryOptions)
	if err != nil {
		return nil, err
	}

	prov, err := provisioning.NewFactoryFromConfigWithOptions(rest, clients.FactoryOptions)
	if err != nil {
		return nil, err
	}

	rke, err := rke.NewFactoryFromConfigWithOptions(rest, clients.FactoryOptions)
	if err != nil {
		return nil, err
	}

	// Pre-register informers used by validators before Start so they are included
	// in the initial cache sync barrier. Without this, lazily-registered informers
	// may not be synced when the HTTP server begins serving admission requests.
	_ = mgmt.Management().V3().AuthConfig().Cache()

	if opts.StartCache {
		if err = mgmt.Start(ctx, 5); err != nil {
			return nil, err
		}
	}

	rbacRestGetter := auth.RBACRestGetter{
		Roles:               clients.RBAC.Role().Cache(),
		RoleBindings:        clients.RBAC.RoleBinding().Cache(),
		ClusterRoles:        clients.RBAC.ClusterRole().Cache(),
		ClusterRoleBindings: clients.RBAC.ClusterRoleBinding().Cache(),
	}

	result := &Clients{
		Clients:                *clients,
		Authorizer:             sarAuthorizer,
		Management:             mgmt.Management().V3(),
		Provisioning:           prov.Provisioning().V1(),
		RKE:                    rke.Rke().V1(),
		MultiClusterManagement: opts.MCMEnabled,
		DefaultResolver:        validation.NewDefaultRuleResolver(rbacRestGetter, rbacRestGetter, rbacRestGetter, rbacRestGetter),
	}

	if opts.MCMEnabled {
		result.RoleTemplateResolver = auth.NewRoleTemplateResolver(mgmt.Management().V3().RoleTemplate().Cache(), clients.RBAC.ClusterRole().Cache())
		result.GlobalRoleResolver = auth.NewGlobalRoleResolver(result.RoleTemplateResolver, mgmt.Management().V3().GlobalRole().Cache())
	}

	return result, nil
}

// newSARAuthorizer caches allowed and denied decisions for the full SubjectAccessReview spec.
func newSARAuthorizer(client authorizationv1.AuthorizationV1Interface) (authorizer.Authorizer, error) {
	return authorizerfactory.DelegatingAuthorizerConfig{
		SubjectAccessReviewClient: client,
		AllowCacheTTL:             sarAllowCacheTTL,
		DenyCacheTTL:              sarDenyCacheTTL,
		// Use one attempt so retries do not consume the admission webhook's timeout.
		WebhookRetryBackoff: &wait.Backoff{Steps: 1},
	}.New()
}
