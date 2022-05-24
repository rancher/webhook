package projectroletemplatebinding

import (
	"strings"
	"time"

	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/trace"
)

func NewValidator(rt v3.RoleTemplateCache, escalationChecker *auth.EscalationChecker) webhook.Handler {
	return &projectRoleTemplateBindingValidator{
		escalationChecker: escalationChecker,
		roleTemplates:     rt,
	}
}

type projectRoleTemplateBindingValidator struct {
	escalationChecker *auth.EscalationChecker
	roleTemplates     v3.RoleTemplateCache
}

func (p *projectRoleTemplateBindingValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("projectRoleTemplateBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	prtb, err := prtbObject(request)
	if err != nil {
		return err
	}

	_, projectNS := clusterFromProject(prtb.ProjectName)

	rt, err := p.roleTemplates.Get(prtb.RoleTemplateName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			response.Allowed = true
			return nil
		}
		return err
	}

	rules, err := p.escalationChecker.RulesFromTemplate(rt)
	if err != nil {
		return err
	}

	return p.escalationChecker.ConfirmNoEscalation(response, request, rules, projectNS)
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

func clusterFromProject(project string) (string, string) {
	pieces := strings.Split(project, ":")
	return pieces[0], pieces[1]
}
