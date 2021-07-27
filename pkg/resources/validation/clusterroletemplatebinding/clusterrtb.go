package clusterroletemplatebinding

import (
	"time"

	"github.com/rancher/webhook/pkg/auth"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/utils/trace"
)

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

	crtb, err := objectsv3.ClusterRoleTemplateBindingFromRequest(request)
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

	rules, err := c.escalationChecker.RulesFromTemplate(rt)
	if err != nil {
		return err
	}

	return c.escalationChecker.ConfirmNoEscalation(response, request, rules, "local")
}
