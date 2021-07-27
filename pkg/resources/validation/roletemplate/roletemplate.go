package roletemplate

import (
	"net/http"
	"time"

	"github.com/rancher/webhook/pkg/auth"
	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/trace"
)

func NewValidator(escalationChecker *auth.EscalationChecker) webhook.Handler {
	return &roleTemplateValidator{
		escalationChecker: escalationChecker,
	}
}

type roleTemplateValidator struct {
	escalationChecker *auth.EscalationChecker
}

func (r *roleTemplateValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("roleTemplateValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	rt, err := objectsv3.RoleTemplateFromRequest(request)
	if err != nil {
		return err
	}

	// object is in the process of being deleted, so admit it
	// this admits update operations that happen to remove finalizers
	if rt.DeletionTimestamp != nil {
		response.Allowed = true
		return nil
	}

	rules, err := r.escalationChecker.RulesFromTemplate(rt)
	if err != nil {
		return err
	}

	// ensure all PolicyRules have at least one verb, otherwise RBAC controllers may encounter issues when creating Roles and ClusterRoles
	for _, rule := range rules {
		if len(rule.Verbs) == 0 {
			response.Result = &metav1.Status{
				Status:  "Failure",
				Message: "RoleTemplate.Rules: PolicyRules must have at least one verb",
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			}
			response.Allowed = false
			return nil
		}
	}

	return r.escalationChecker.ConfirmNoEscalation(response, request, rules, "")
}
