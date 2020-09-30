package admission

import (
	"context"
	"net/http"

	"github.com/rancher/rancher/pkg/apis/management.cattle.io"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/authentication"
	"github.com/rancher/webhook/pkg/cluster"
	mgmtcontrollers "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io"
	k8srbacv1 "github.com/rancher/webhook/pkg/generated/controllers/rbac.authorization.k8s.io"
	"github.com/rancher/wrangler-api/pkg/generated/controllers/rbac"
	"github.com/rancher/wrangler/pkg/start"
	"github.com/rancher/wrangler/pkg/webhook"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	rbacregistryvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
)

func Validation(ctx context.Context, cfg *rest.Config) (http.Handler, error) {
	grb, err := mgmtcontrollers.NewFactoryFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	r, err := rbac.NewFactoryFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	k8srbac, err := k8srbacv1.NewFactoryFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	rbacRestGetter := authentication.RBACRestGetter{
		Roles:               r.Rbac().V1().Role().Cache(),
		RoleBindings:        r.Rbac().V1().RoleBinding().Cache(),
		ClusterRoles:        r.Rbac().V1().ClusterRole().Cache(),
		ClusterRoleBindings: r.Rbac().V1().ClusterRoleBinding().Cache(),
	}

	ruleResolver := rbacregistryvalidation.NewDefaultRuleResolver(rbacRestGetter, rbacRestGetter, rbacRestGetter, rbacRestGetter)

	escalationChecker := auth.NewEscalationChecker(ruleResolver, grb.Management().V3().RoleTemplate().Cache(), k8srbac.Rbac().V1().ClusterRole().Cache())

	globalRoleBindings := auth.NewGRBValidator(grb.Management().V3().GlobalRole().Cache(), escalationChecker)
	prtbs := auth.NewPRTBValidator(grb.Management().V3().RoleTemplate().Cache(), escalationChecker)
	crtbs := auth.NewCRTBValidator(grb.Management().V3().RoleTemplate().Cache(), escalationChecker)
	roleTemplates := auth.NewRoleTemplateValidator(escalationChecker)

	k8s, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	clusters := cluster.NewClusterValidator(k8s.AuthorizationV1().SubjectAccessReviews())

	router := webhook.NewRouter()
	router.Kind("Cluster").Group(management.GroupName).Type(&v3.Cluster{}).Handle(clusters)
	router.Kind("RoleTemplate").Group(management.GroupName).Type(&v3.RoleTemplate{}).Handle(roleTemplates)
	router.Kind("GlobalRoleBinding").Group(management.GroupName).Type(&v3.GlobalRoleBinding{}).Handle(globalRoleBindings)
	router.Kind("ClusterRoleTemplateBinding").Group(management.GroupName).Type(&v3.ClusterRoleTemplateBinding{}).Handle(crtbs)
	router.Kind("ProjectRoleTemplateBinding").Group(management.GroupName).Type(&v3.ProjectRoleTemplateBinding{}).Handle(prtbs)

	starters := []start.Starter{r, grb, k8srbac}
	start.All(ctx, 5, starters...)
	return router, nil
}
