package clients

import (
	"context"

	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io"
	managementv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/generated/controllers/provisioning.cattle.io"
	provv1 "github.com/rancher/webhook/pkg/generated/controllers/provisioning.cattle.io/v1"
	"github.com/rancher/wrangler/v2/pkg/clients"
	"github.com/rancher/wrangler/v2/pkg/schemes"
	v1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/client-go/rest"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

type Clients struct {
	clients.Clients

	MultiClusterManagement bool
	Management             managementv3.Interface
	Provisioning           provv1.Interface
	RoleTemplateResolver   *auth.RoleTemplateResolver
	GlobalRoleResolver     *auth.GlobalRoleResolver
	DefaultResolver        validation.AuthorizationRuleResolver
}

func New(ctx context.Context, rest *rest.Config, mcmEnabled bool) (*Clients, error) {
	clients, err := clients.NewFromConfig(rest, nil)
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

	if err = mgmt.Start(ctx, 5); err != nil {
		return nil, err
	}

	rbacRestGetter := auth.RBACRestGetter{
		Roles:               clients.RBAC.Role().Cache(),
		RoleBindings:        clients.RBAC.RoleBinding().Cache(),
		ClusterRoles:        clients.RBAC.ClusterRole().Cache(),
		ClusterRoleBindings: clients.RBAC.ClusterRoleBinding().Cache(),
	}

	result := &Clients{
		Clients:                *clients,
		Management:             mgmt.Management().V3(),
		Provisioning:           prov.Provisioning().V1(),
		MultiClusterManagement: mcmEnabled,
		DefaultResolver:        validation.NewDefaultRuleResolver(rbacRestGetter, rbacRestGetter, rbacRestGetter, rbacRestGetter),
	}

	if mcmEnabled {
		result.RoleTemplateResolver = auth.NewRoleTemplateResolver(mgmt.Management().V3().RoleTemplate().Cache(), clients.RBAC.ClusterRole().Cache(), mgmt.Management().V3().Feature().Cache())
		result.GlobalRoleResolver = auth.NewGlobalRoleResolver(result.RoleTemplateResolver, mgmt.Management().V3().GlobalRole().Cache())
	}

	return result, nil
}
