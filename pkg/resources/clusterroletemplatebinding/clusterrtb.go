package clusterroletemplatebinding

import (
	"time"

	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/utils/trace"
)

var clusterRoleTemplateBindingGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "clusterroletemplatebindings",
}

func NewValidator(rt v3.RoleTemplateCache, escalationChecker *auth.EscalationChecker) webhook.Handler {
	return &clusterRoleTemplateBindingValidator{
		escalationChecker: escalationChecker,
		roleTemplates:     rt,
	}
}

type clusterRoleTemplateBindingValidator struct {
	escalationChecker *auth.EscalationChecker
	roleTemplates     v3.RoleTemplateCache
}

func (c *clusterRoleTemplateBindingValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("clusterRoleTemplateBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	crtb, err := crtbObject(request)
	if err != nil {
		return err
	}

	rt, err := c.roleTemplates.Get(crtb.RoleTemplateName)
	if err != nil {
		if apierrors.IsNotFound(err) {
			response.Allowed = true
			return nil
		}
		return err
	}

	rules, err := c.escalationChecker.RulesFromTemplate(rt)
	if err != nil {
		return err
	}

	allowed, err := c.escalationChecker.EscalationAuthorized(response, request, clusterRoleTemplateBindingGVR, crtb.ClusterName)
	if err != nil {
		logrus.Warnf("Failed to check for the 'escalate' verb on ClusterRoleTemplateBinding: %v", err)
	}

	if allowed {
		response.Allowed = true
		return nil
	}

	return c.escalationChecker.ConfirmNoEscalation(response, request, rules, crtb.ClusterName)
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
