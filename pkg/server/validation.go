package server

import (
	"net/http"

	"github.com/rancher/rancher/pkg/apis/management.cattle.io"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/apis/provisioning.cattle.io"
	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/rancher/webhook/pkg/resources/validation/cluster"
	"github.com/rancher/webhook/pkg/resources/validation/clusterroletemplatebinding"
	"github.com/rancher/webhook/pkg/resources/validation/globalrole"
	"github.com/rancher/webhook/pkg/resources/validation/globalrolebinding"
	"github.com/rancher/webhook/pkg/resources/validation/projectroletemplatebinding"
	"github.com/rancher/webhook/pkg/resources/validation/roletemplate"
	"github.com/rancher/wrangler/pkg/webhook"
)

func Validation(clients *clients.Clients) (http.Handler, error) {
	clusters := cluster.NewValidator(clients.K8s.AuthorizationV1().SubjectAccessReviews())
	router := webhook.NewRouter()
	router.Kind("Cluster").Group(management.GroupName).Type(&v3.Cluster{}).Handle(clusters)

	if clients.MultiClusterManagement {
		globalRoleBindings := globalrolebinding.NewValidator(clients.Management.GlobalRole().Cache(), clients.EscalationChecker)
		globalRoles := globalrole.NewValidator()
		prtbs := projectroletemplatebinding.NewValidator(clients.Management.RoleTemplate().Cache(), clients.EscalationChecker)
		crtbs := clusterroletemplatebinding.NewValidator(clients.Management.RoleTemplate().Cache(), clients.EscalationChecker)
		roleTemplates := roletemplate.NewValidator(clients.EscalationChecker)
		provisioningCluster := cluster.NewProvisioningClusterValidator()

		router.Kind("RoleTemplate").Group(management.GroupName).Type(&v3.RoleTemplate{}).Handle(roleTemplates)
		router.Kind("GlobalRoleBinding").Group(management.GroupName).Type(&v3.GlobalRoleBinding{}).Handle(globalRoleBindings)
		router.Kind("GlobalRole").Group(management.GroupName).Type(&v3.GlobalRole{}).Handle(globalRoles)
		router.Kind("ClusterRoleTemplateBinding").Group(management.GroupName).Type(&v3.ClusterRoleTemplateBinding{}).Handle(crtbs)
		router.Kind("ProjectRoleTemplateBinding").Group(management.GroupName).Type(&v3.ProjectRoleTemplateBinding{}).Handle(prtbs)
		router.Kind("Cluster").Group(provisioning.GroupName).Type(&v1.Cluster{}).Handle(provisioningCluster)
	}

	return router, nil
}
