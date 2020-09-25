package admission

import (
	"net/http"

	"github.com/rancher/rancher/pkg/apis/management.cattle.io"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/cluster"
	mgmtcontrollers "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io"
	"github.com/rancher/wrangler-api/pkg/generated/controllers/rbac"
	"github.com/rancher/wrangler/pkg/webhook"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

func Validation(cfg *rest.Config) (http.Handler, error) {
	grb, err := mgmtcontrollers.NewFactoryFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	r, err := rbac.NewFactoryFromConfig(cfg)
	if err != nil {
		return nil, err
	}

	globalRoleBindings, err := auth.NewGRBValidator(grb.Management().V3().GlobalRole(), r.Rbac())
	if err != nil {
		return nil, err
	}

	k8s, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, err
	}

	sar := k8s.AuthorizationV1().SubjectAccessReviews()

	clusters := cluster.NewClusterValidator(sar)
	prtbs := auth.NewPRTBalidator(sar)
	crtbs := auth.NewCRTBalidator(sar)

	router := webhook.NewRouter()
	router.Kind("Cluster").Group(management.GroupName).Type(&v3.Cluster{}).Handle(clusters)
	router.Kind("GlobalRoleBinding").Group(management.GroupName).Type(&v3.GlobalRoleBinding{}).Handle(globalRoleBindings)
	router.Kind("ProjectRoleTemplateBinding").Group(management.GroupName).Type(&v3.ProjectRoleTemplateBinding{}).Handle(prtbs)
	router.Kind("ClusterRoleTemplateBinding").Group(management.GroupName).Type(&v3.ClusterRoleTemplateBinding{}).Handle(crtbs)

	return router, nil
}
