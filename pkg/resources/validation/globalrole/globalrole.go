package globalrole

import (
	"net/http"
	"time"

	objectsv3 "github.com/rancher/webhook/pkg/generated/objects/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/trace"
)

func NewValidator() webhook.Handler {
	return &globalRoleValidator{}
}

type globalRoleValidator struct{}

func (grv *globalRoleValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("globalRoleValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	newGR, err := objectsv3.GlobalRoleFromRequest(request)
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

	response.Allowed = true
	return nil
}
