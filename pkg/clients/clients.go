package clients

import (
	"context"

	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io"
	managementv3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/clients"
	"github.com/rancher/wrangler/pkg/schemes"
	v1 "k8s.io/api/admissionregistration/v1"
	"k8s.io/client-go/rest"
	rbacregistryvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
)

type Clients struct {
	clients.Clients

	Management        managementv3.Interface
	EscalationChecker *auth.EscalationChecker
}

func New(ctx context.Context, rest *rest.Config) (*Clients, error) {
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

	if err = mgmt.Start(ctx, 5); err != nil {
		return nil, err
	}

	rbacRestGetter := auth.RBACRestGetter{
		Roles:               clients.RBAC.Role().Cache(),
		RoleBindings:        clients.RBAC.RoleBinding().Cache(),
		ClusterRoles:        clients.RBAC.ClusterRole().Cache(),
		ClusterRoleBindings: clients.RBAC.ClusterRoleBinding().Cache(),
	}

	ruleResolver := rbacregistryvalidation.NewDefaultRuleResolver(rbacRestGetter, rbacRestGetter, rbacRestGetter, rbacRestGetter)
	escalationChecker := auth.NewEscalationChecker(ruleResolver,
		mgmt.Management().V3().RoleTemplate().Cache(), clients.RBAC.ClusterRole().Cache(), clients.K8s.AuthorizationV1().SubjectAccessReviews())

	return &Clients{
		Clients:           *clients,
		Management:        mgmt.Management().V3(),
		EscalationChecker: escalationChecker,
	}, nil
}
