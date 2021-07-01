package server

import (
	"net/http"

	"github.com/rancher/rancher/pkg/apis/management.cattle.io"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/rancher/webhook/pkg/resources/cluster"
	"github.com/rancher/webhook/pkg/resources/clusterroletemplatebinding"
	"github.com/rancher/webhook/pkg/resources/globalrole"
	"github.com/rancher/webhook/pkg/resources/globalrolebinding"
	"github.com/rancher/webhook/pkg/resources/projectroletemplatebinding"
	"github.com/rancher/webhook/pkg/resources/roletemplate"
	"github.com/rancher/wrangler/pkg/webhook"
)

func Validation(clients *clients.Clients) (http.Handler, error) {
	clusters := cluster.NewValidator(clients.K8s.AuthorizationV1().SubjectAccessReviews())
	roleTemplates := roletemplate.NewValidator(clients.EscalationChecker)
	globalRoles := globalrole.NewValidator()
	globalRoleBindings := globalrolebinding.NewValidator(clients.Management.GlobalRole().Cache(), clients.EscalationChecker)
	crtbs := clusterroletemplatebinding.NewValidator(clients.Management.RoleTemplate().Cache(), clients.EscalationChecker)
	prtbs := projectroletemplatebinding.NewValidator(clients.Management.RoleTemplate().Cache(), clients.EscalationChecker)

	router := webhook.NewRouter()
	router.Kind("Cluster").Group(management.GroupName).Type(&v3.Cluster{}).Handle(access(clusters))
	router.Kind("RoleTemplate").Group(management.GroupName).Type(&v3.RoleTemplate{}).Handle(access(roleTemplates))
	router.Kind("GlobalRole").Group(management.GroupName).Type(&v3.GlobalRole{}).Handle(access(globalRoles))
	router.Kind("GlobalRoleBinding").Group(management.GroupName).Type(&v3.GlobalRoleBinding{}).Handle(access(globalRoleBindings))
	router.Kind("ClusterRoleTemplateBinding").Group(management.GroupName).Type(&v3.ClusterRoleTemplateBinding{}).Handle(access(crtbs))
	router.Kind("ProjectRoleTemplateBinding").Group(management.GroupName).Type(&v3.ProjectRoleTemplateBinding{}).Handle(access(prtbs))

	return router, nil
}
