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
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/nodedriver"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/podsecurityadmissionconfigurationtemplate"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/projectroletemplatebinding"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/roletemplate"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/setting"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/userattribute"
	provisioningCluster "github.com/rancher/webhook/pkg/resources/provisioning.cattle.io/v1/cluster"
	"github.com/rancher/webhook/pkg/resources/rke-machine-config.cattle.io/v1/machineconfig"
)

// Validation returns a list of all ValidatingAdmissionHandlers used by the webhook.
func Validation(clients *clients.Clients) ([]admission.ValidatingAdmissionHandler, error) {
	handlers := []admission.ValidatingAdmissionHandler{
		feature.NewValidator(clients.DefaultResolver),
		managementCluster.NewValidator(clients.K8s.AuthorizationV1().SubjectAccessReviews(), clients.Management.PodSecurityAdmissionConfigurationTemplate().Cache()),
		provisioningCluster.NewProvisioningClusterValidator(clients),
		machineconfig.NewValidator(),
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
		secrets := secret.NewValidator(clients.RBAC.Role().Cache(), clients.RBAC.RoleBinding().Cache())
		nodeDriver := nodedriver.NewValidator(clients.Management.Node().Cache(), clients.Dynamic)
		userAttribute := userattribute.NewValidator()
		setting := setting.NewValidator()
		handlers = append(handlers, psact, globalRoles, globalRoleBindings, prtbs, crtbs, roleTemplates, secrets, nodeDriver, userAttribute, setting)
	}
	return handlers, nil
}

// Mutation returns a list of all MutatingAdmissionHandlers used by the webhook.
func Mutation(clients *clients.Clients) ([]admission.MutatingAdmissionHandler, error) {
	mutators := []admission.MutatingAdmissionHandler{
		provisioningCluster.NewProvisioningClusterMutator(clients.Core.Secret(), clients.Management.PodSecurityAdmissionConfigurationTemplate().Cache()),
		managementCluster.NewManagementClusterMutator(clients.Management.PodSecurityAdmissionConfigurationTemplate().Cache()),
		fleetworkspace.NewMutator(clients),
		&machineconfig.Mutator{},
	}

	if clients.MultiClusterManagement {
		mutators = append(mutators, secret.NewMutator(clients.RBAC.Role(), clients.RBAC.RoleBinding()))
	}
	return mutators, nil
}
