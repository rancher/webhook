package server

import (
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/clients"
	mutationCluster "github.com/rancher/webhook/pkg/resources/mutation/cluster"
	"github.com/rancher/webhook/pkg/resources/mutation/fleetworkspace"
	"github.com/rancher/webhook/pkg/resources/mutation/machineconfigs"
	"github.com/rancher/webhook/pkg/resources/mutation/secret"
	"github.com/rancher/webhook/pkg/resources/validation/cluster"
	"github.com/rancher/webhook/pkg/resources/validation/clusterroletemplatebinding"
	"github.com/rancher/webhook/pkg/resources/validation/feature"
	"github.com/rancher/webhook/pkg/resources/validation/globalrole"
	"github.com/rancher/webhook/pkg/resources/validation/globalrolebinding"
	"github.com/rancher/webhook/pkg/resources/validation/machineconfig"
	"github.com/rancher/webhook/pkg/resources/validation/projectroletemplatebinding"
	"github.com/rancher/webhook/pkg/resources/validation/roletemplate"
)

// Validation returns a list of all ValidatingAdmissionHandlers used by the webhook.
func Validation(clients *clients.Clients) ([]admission.ValidatingAdmissionHandler, error) {
	handlers := []admission.ValidatingAdmissionHandler{
		&feature.Validator{},
		cluster.NewValidator(clients.K8s.AuthorizationV1().SubjectAccessReviews()),
		cluster.NewProvisioningClusterValidator(clients),
		&machineconfig.Validator{},
	}
	if clients.MultiClusterManagement {
		globalRoles := globalrole.NewValidator(clients.DefaultResolver)
		globalRoleBindings := globalrolebinding.NewValidator(clients.Management.GlobalRole().Cache(), clients.DefaultResolver)
		prtbs := projectroletemplatebinding.NewValidator(clients.Management.ProjectRoleTemplateBinding().Cache(),
			clients.Management.ClusterRoleTemplateBinding().Cache(), clients.DefaultResolver, clients.RoleTemplateResolver)
		crtbs := clusterroletemplatebinding.NewValidator(clients.Management.ClusterRoleTemplateBinding().Cache(),
			clients.DefaultResolver, clients.RoleTemplateResolver)
		roleTemplates := roletemplate.NewValidator(clients.DefaultResolver, clients.RoleTemplateResolver, clients.K8s.AuthorizationV1().SubjectAccessReviews())

		handlers = append(handlers, globalRoles, globalRoleBindings, prtbs, crtbs, roleTemplates)
	}
	return handlers, nil
}

// Mutation returns a list of all MutatingAdmissionHandlers used by the webhook.
func Mutation(clients *clients.Clients) ([]admission.MutatingAdmissionHandler, error) {
	return []admission.MutatingAdmissionHandler{
		&mutationCluster.Mutator{},
		fleetworkspace.NewMutator(clients),
		&secret.Mutator{},
		&machineconfigs.Mutator{},
	}, nil
}
