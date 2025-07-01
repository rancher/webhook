package server

import (
	"github.com/rancher/webhook/pkg/admission"
	"github.com/rancher/webhook/pkg/clients"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/resolvers"
	auditpolicy "github.com/rancher/webhook/pkg/resources/auditlog.cattle.io/v1/auditpolicy"
	"github.com/rancher/webhook/pkg/resources/catalog.cattle.io/v1/clusterrepo"
	"github.com/rancher/webhook/pkg/resources/cluster.cattle.io/v3/clusterauthtoken"
	nshandler "github.com/rancher/webhook/pkg/resources/core/v1/namespace"
	"github.com/rancher/webhook/pkg/resources/core/v1/secret"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/authconfig"
	managementCluster "github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/cluster"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/clusterproxyconfig"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/clusterroletemplatebinding"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/feature"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/fleetworkspace"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/globalrole"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/globalrolebinding"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/nodedriver"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/podsecurityadmissionconfigurationtemplate"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/project"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/projectroletemplatebinding"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/roletemplate"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/setting"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/token"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/userattribute"
	"github.com/rancher/webhook/pkg/resources/management.cattle.io/v3/users"
	provisioningCluster "github.com/rancher/webhook/pkg/resources/provisioning.cattle.io/v1/cluster"
	"github.com/rancher/webhook/pkg/resources/rbac.authorization.k8s.io/v1/clusterrole"
	"github.com/rancher/webhook/pkg/resources/rbac.authorization.k8s.io/v1/clusterrolebinding"
	"github.com/rancher/webhook/pkg/resources/rbac.authorization.k8s.io/v1/role"
	"github.com/rancher/webhook/pkg/resources/rbac.authorization.k8s.io/v1/rolebinding"
	"github.com/rancher/webhook/pkg/resources/rke-machine-config.cattle.io/v1/machineconfig"
)

// Validation returns a list of all ValidatingAdmissionHandlers used by the webhook.
func Validation(clients *clients.Clients) ([]admission.ValidatingAdmissionHandler, error) {
	var userCache v3.UserCache
	var settingCache v3.SettingCache
	if clients.MultiClusterManagement {
		userCache = clients.Management.User().Cache()
		settingCache = clients.Management.Setting().Cache()
	}

	clusters := managementCluster.NewValidator(
		clients.K8s.AuthorizationV1().SubjectAccessReviews(),
		clients.Management.PodSecurityAdmissionConfigurationTemplate().Cache(),
		userCache,
		clients.Management.Feature().Cache(),
		settingCache,
	)

	handlers := []admission.ValidatingAdmissionHandler{
		feature.NewValidator(),
		clusters,
		provisioningCluster.NewProvisioningClusterValidator(clients),
		machineconfig.NewValidator(),
		nshandler.NewValidator(clients.K8s.AuthorizationV1().SubjectAccessReviews()),
		clusterrepo.NewValidator(),
		auditpolicy.NewValidator(),
	}

	if clients.MultiClusterManagement {
		crtbResolver := resolvers.NewCRTBRuleResolver(clients.Management.ClusterRoleTemplateBinding().Cache(), clients.RoleTemplateResolver)
		prtbResolver := resolvers.NewPRTBRuleResolver(clients.Management.ProjectRoleTemplateBinding().Cache(), clients.RoleTemplateResolver)
		grbResolvers := resolvers.NewGRBRuleResolvers(clients.Management.GlobalRoleBinding().Cache(), clients.GlobalRoleResolver)

		handlers = append(
			handlers,
			clusterproxyconfig.NewValidator(clients.Management.ClusterProxyConfig().Cache()),
			podsecurityadmissionconfigurationtemplate.NewValidator(clients.Management.Cluster().Cache(), clients.Provisioning.Cluster().Cache()),
			globalrole.NewValidator(clients.DefaultResolver, grbResolvers, clients.K8s.AuthorizationV1().SubjectAccessReviews(), clients.GlobalRoleResolver),
			globalrolebinding.NewValidator(clients.DefaultResolver, grbResolvers, clients.K8s.AuthorizationV1().SubjectAccessReviews(), clients.GlobalRoleResolver),
			projectroletemplatebinding.NewValidator(prtbResolver, crtbResolver, clients.DefaultResolver, clients.RoleTemplateResolver, clients.Management.Cluster().Cache(), clients.Management.Project().Cache()),
			clusterroletemplatebinding.NewValidator(crtbResolver, clients.DefaultResolver, clients.RoleTemplateResolver, clients.Management.GlobalRoleBinding().Cache(), clients.Management.Cluster().Cache()),
			roletemplate.NewValidator(clients.DefaultResolver, clients.RoleTemplateResolver, clients.K8s.AuthorizationV1().SubjectAccessReviews(), clients.Management.GlobalRole().Cache()),
			secret.NewValidator(clients.RBAC.Role().Cache(), clients.RBAC.RoleBinding().Cache()),
			nodedriver.NewValidator(clients.Management.Node().Cache(), clients.Dynamic),
			project.NewValidator(clients.Management.Cluster().Cache(), clients.Management.User().Cache()),
			role.NewValidator(),
			rolebinding.NewValidator(),
			setting.NewValidator(clients.Management.Cluster().Cache(), clients.Management.Setting().Cache()),
			token.NewValidator(),
			userattribute.NewValidator(),
			clusterrole.NewValidator(),
			clusterrolebinding.NewValidator(),
			authconfig.NewValidator(),
			users.NewValidator(clients.Management.UserAttribute().Cache(), clients.K8s.AuthorizationV1().SubjectAccessReviews(), clients.DefaultResolver),
		)
	} else {
		handlers = append(handlers, clusterauthtoken.NewValidator())
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
		secrets := secret.NewMutator(clients.RBAC.Role(), clients.RBAC.RoleBinding())
		projects := project.NewMutator(clients.Core.Namespace().Cache(), clients.Management.RoleTemplate().Cache(), clients.Management.Project().Cache())
		grbs := globalrolebinding.NewMutator(clients.Management.GlobalRole().Cache())
		mutators = append(mutators, secrets, projects, grbs)
	}

	return mutators, nil
}
