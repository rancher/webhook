package server

import (
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/rancher/webhook/pkg/resolvers"
	nshandler "github.com/rancher/webhook/pkg/resources/core/v1/namespace"
	"github.com/rancher/webhook/pkg/resources/core/v1/secret"
	managementCluster "github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/cluster"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/clusterroletemplatebinding"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/feature"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/fleetworkspace"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/globalrole"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/globalrolebinding"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/podsecurityadmissionconfigurationtemplate"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/projectroletemplatebinding"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/roletemplate"
	provisioningCluster "github.com/rancher/webhook/pkg/resources/provisioning.cattle.io/v1/cluster"
	"github.com/rancher/webhook/pkg/resources/rke-machine-config.cattle.io/v1/machineconfig"
)

// Validation returns a list of all ValidatingAdmissionHandlers used by the webhook.
func Validation(clients *clients.Clients) ([]admission.ValidatingAdmissionHandler, error) {
	handlers := []admission.ValidatingAdmissionHandler{
		&feature.Validator{},
		managementCluster.NewValidator(clients.K8s.AuthorizationV1().SubjectAccessReviews(), clients.Management.PodSecurityAdmissionConfigurationTemplate().Cache()),
		provisioningCluster.NewProvisioningClusterValidator(clients),
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
	handlers := []admission.MutatingAdmissionHandler{
		provisioningCluster.NewProvisioningClusterMutator(clients.Core.Secret(), clients.Management.PodSecurityAdmissionConfigurationTemplate().Cache()),
		managementCluster.NewManagementClusterMutator(clients.Management.PodSecurityAdmissionConfigurationTemplate().Cache()),
		fleetworkspace.NewMutator(clients),
		&machineconfig.Mutator{},
	}

	if clients.MultiClusterManagement {
		handlers = append(handlers, &secret.Mutator{})
	}

	return handlers, nil
}
