package roletemplate

import (
	"time"

	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
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
