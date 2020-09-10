package admission

import (
	"net/http"

	"github.com/rancher/rancher/pkg/apis/management.cattle.io"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

func Validation(sar authorizationv1.SubjectAccessReviewInterface) http.Handler {
	clusters := newClusterValidator(sar)

	router := webhook.NewRouter()
	router.Kind("Cluster").Group(management.GroupName).Type(&v3.Cluster{}).Handle(clusters)

	return router
}
