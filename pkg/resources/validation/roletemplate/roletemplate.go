package roletemplate

import (
	"net/http"
	"time"

	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
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

	rt, err := roleTemplateObject(request)
	if err != nil {
		return err
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

func roleTemplateObject(request *webhook.Request) (*rancherv3.RoleTemplate, error) {
	var rt runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		rt, err = request.DecodeOldObject()
	} else {
		rt, err = request.DecodeObject()
	}
	return rt.(*rancherv3.RoleTemplate), err
}
