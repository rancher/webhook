package server

import (
	"net/http"

	"github.com/rancher/rancher/pkg/apis/management.cattle.io"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/rancher/webhook/pkg/resources/cluster"
	"github.com/rancher/webhook/pkg/resources/clusterroletemplatebinding"
	"github.com/rancher/webhook/pkg/resources/globalrolebinding"
	"github.com/rancher/webhook/pkg/resources/projectroletemplatebinding"
	"github.com/rancher/webhook/pkg/resources/roletemplate"
	"github.com/rancher/wrangler/pkg/webhook"
)

func Validation(clients *clients.Clients) (http.Handler, error) {
	clusters := cluster.NewValidator(clients.K8s.AuthorizationV1().SubjectAccessReviews())

	router := webhook.NewRouter()
	router.Kind("Cluster").Group(management.GroupName).Type(&v3.Cluster{}).Handle(clusters)

	if clients.MultiClusterManagement {
		globalRoleBindings := globalrolebinding.NewValidator(clients.Management.GlobalRole().Cache(), clients.EscalationChecker)
		prtbs := projectroletemplatebinding.NewValidator(clients.Management.RoleTemplate().Cache(), clients.EscalationChecker)
		crtbs := clusterroletemplatebinding.NewValidator(clients.Management.RoleTemplate().Cache(), clients.EscalationChecker)
		roleTemplates := roletemplate.NewValidator(clients.EscalationChecker)
		router.Kind("RoleTemplate").Group(management.GroupName).Type(&v3.RoleTemplate{}).Handle(roleTemplates)
		router.Kind("GlobalRoleBinding").Group(management.GroupName).Type(&v3.GlobalRoleBinding{}).Handle(globalRoleBindings)
		router.Kind("ClusterRoleTemplateBinding").Group(management.GroupName).Type(&v3.ClusterRoleTemplateBinding{}).Handle(crtbs)
		router.Kind("ProjectRoleTemplateBinding").Group(management.GroupName).Type(&v3.ProjectRoleTemplateBinding{}).Handle(prtbs)
	}

	return router, nil
}
