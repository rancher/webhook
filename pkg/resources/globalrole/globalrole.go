package globalrole

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
	return &globalRoleValidator{
		escalationChecker: escalationChecker,
	}
}

type globalRoleValidator struct {
	escalationChecker *auth.EscalationChecker
}

func (grv *globalRoleValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("globalRoleValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	newGR, err := grObject(request)
	if err != nil {
		return err
	}

	// object is in the process of being deleted, so admit it
	// this admits update operations that happen to remove finalizers
	if newGR.DeletionTimestamp != nil {
		response.Allowed = true
		return nil
	}

	// ensure all PolicyRules have at least one verb, otherwise RBAC controllers may encounter issues when creating Roles and ClusterRoles
	for _, rule := range newGR.Rules {
		if len(rule.Verbs) == 0 {
			response.Result = &metav1.Status{
				Status:  "Failure",
				Message: "GlobalRole.Rules: PolicyRules must have at least one verb",
				Reason:  metav1.StatusReasonBadRequest,
				Code:    http.StatusBadRequest,
			}
			response.Allowed = false
			return nil
		}
	}

	return grv.escalationChecker.ConfirmNoEscalation(response, request, newGR.Rules, "")
}

func grObject(request *webhook.Request) (*rancherv3.GlobalRole, error) {
	var gr runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		gr, err = request.DecodeOldObject()
	} else {
		gr, err = request.DecodeObject()
	}
	return gr.(*rancherv3.GlobalRole), err
}
