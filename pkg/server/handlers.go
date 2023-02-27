package server

import (
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/rancher/webhook/pkg/resolvers"
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
	nshandler "github.com/rancher/webhook/pkg/resources/validation/namespace"
	"github.com/rancher/webhook/pkg/resources/validation/podsecurityadmissionconfigurationtemplate"
	"github.com/rancher/webhook/pkg/resources/validation/projectroletemplatebinding"
	"github.com/rancher/webhook/pkg/resources/validation/roletemplate"
)

// Validation returns a list of all ValidatingAdmissionHandlers used by the webhook.
func Validation(clients *clients.Clients) ([]admission.ValidatingAdmissionHandler, error) {
	handlers := []admission.ValidatingAdmissionHandler{
		&feature.Validator{},
		cluster.NewValidator(clients.K8s.AuthorizationV1().SubjectAccessReviews(), clients.Management.PodSecurityAdmissionConfigurationTemplate().Cache()),
		cluster.NewProvisioningClusterValidator(clients),
		&machineconfig.Validator{},
		nshandler.NewValidator(clients.K8s.AuthorizationV1().SubjectAccessReviews()),
	}

	if clients.MultiClusterManagement {
		crtbResolver := resolvers.NewCRTBRuleResolver(clients.Management.ClusterRoleTemplateBinding().Cache(), clients.RoleTemplateResolver)
		prtbResolver := resolvers.NewPRTBRuleResolver(clients.Management.ProjectRoleTemplateBinding().Cache(), clients.RoleTemplateResolver)
		psact := podsecurityadmissionconfigurationtemplate.NewValidator(clients.Management.Cluster().Cache(), clients.Provisioning.Cluster().Cache())
		globalRoles := globalrole.NewValidator(clients.DefaultResolver)
		globalRoleBindings := globalrolebinding.NewValidator(clients.Management.GlobalRole().Cache(), clients.DefaultResolver)
		prtbs := projectroletemplatebinding.NewValidator(prtbResolver, crtbResolver, clients.DefaultResolver, clients.RoleTemplateResolver)
		crtbs := clusterroletemplatebinding.NewValidator(crtbResolver, clients.DefaultResolver, clients.RoleTemplateResolver)
		roleTemplates := roletemplate.NewValidator(clients.DefaultResolver, clients.RoleTemplateResolver, clients.K8s.AuthorizationV1().SubjectAccessReviews())

		handlers = append(handlers, psact, globalRoles, globalRoleBindings, prtbs, crtbs, roleTemplates)
	}
	return handlers, nil
}

// Mutation returns a list of all MutatingAdmissionHandlers used by the webhook.
func Mutation(clients *clients.Clients) ([]admission.MutatingAdmissionHandler, error) {
	return []admission.MutatingAdmissionHandler{
		mutationCluster.NewProvisioningClusterMutator(clients.Core.Secret(), clients.Management.PodSecurityAdmissionConfigurationTemplate().Cache()),
		mutationCluster.NewManagementClusterMutator(clients.Management.PodSecurityAdmissionConfigurationTemplate().Cache()),
		fleetworkspace.NewMutator(clients),
		&secret.Mutator{},
		&machineconfigs.Mutator{},
	}, nil
}
