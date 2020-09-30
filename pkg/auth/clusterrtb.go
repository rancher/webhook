package auth

import (
	"time"

	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/trace"
)

func NewCRTBValidator(rt v3.RoleTemplateCache, escalationChecker *EscalationChecker) webhook.Handler {
	return &clusterRoleTemplateBindingValidator{
		escalationChecker: escalationChecker,
		roleTemplates:     rt,
	}
}

type clusterRoleTemplateBindingValidator struct {
	escalationChecker *EscalationChecker
	roleTemplates     v3.RoleTemplateCache
}

func (c *clusterRoleTemplateBindingValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("clusterRoleTemplateBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	crtb, err := crtbObject(request)
	if err != nil {
		return err
	}

	if crtb.ClusterName != "local" {
		response.Allowed = true
		return nil
	}

	rt, err := c.roleTemplates.Get(crtb.RoleTemplateName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			response.Allowed = true
			return nil
		}
		return err
	}

	rules, err := c.escalationChecker.rulesFromTemplate(rt)
	if err != nil {
		return err
	}

	return c.escalationChecker.confirmNoEscalation(response, request, rules, "local")
}

func crtbObject(request *webhook.Request) (*rancherv3.ClusterRoleTemplateBinding, error) {
	var crtb runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		crtb, err = request.DecodeOldObject()
	} else {
		crtb, err = request.DecodeObject()
	}
	return crtb.(*rancherv3.ClusterRoleTemplateBinding), err
}
