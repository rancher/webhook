package auth

import (
	"strings"
	"time"

	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/trace"
)

func NewPRTBalidator(sar authorizationv1.SubjectAccessReviewInterface) webhook.Handler {
	return &projectRoleTemplateBindingValidator{
		sar: sar,
	}
}

type projectRoleTemplateBindingValidator struct {
	sar authorizationv1.SubjectAccessReviewInterface
}

func (p *projectRoleTemplateBindingValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("projectRoleTemplateBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(1 * time.Second)

	prtb, err := prtbObject(request)
	if err != nil {
		return err
	}

	clusterID := clusterFromProject(prtb.ProjectName)

	if clusterID != "local" {
		response.Allowed = true
		return nil
	}

	return adminAccessCheck(p.sar, response, request)
}

func prtbObject(request *webhook.Request) (*rancherv3.ProjectRoleTemplateBinding, error) {
	var prtb runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		prtb, err = request.DecodeOldObject()
	} else {
		prtb, err = request.DecodeObject()
	}
	return prtb.(*rancherv3.ProjectRoleTemplateBinding), err
}

func clusterFromProject(project string) string {
	pieces := strings.Split(project, ":")
	return pieces[0]
}
