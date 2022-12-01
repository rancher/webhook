package roletemplate

import (
	"net/http"
	"time"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/wrangler/pkg/webhook"
	"github.com/sirupsen/logrus"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/trace"
)

var roleTemplateGVR = schema.GroupVersionResource{
	Group:    "management.cattle.io",
	Version:  "v3",
	Resource: "roletemplates",
}

func NewValidator(resolver validation.AuthorizationRuleResolver, roleTemplateResolver *auth.RoleTemplateResolver,
	sar authorizationv1.SubjectAccessReviewInterface) webhook.Handler {
	return &roleTemplateValidator{
		resolver:             resolver,
		roleTemplateResolver: roleTemplateResolver,
		sar:                  sar,
	}
}

type roleTemplateValidator struct {
	resolver             validation.AuthorizationRuleResolver
	roleTemplateResolver *auth.RoleTemplateResolver
	sar                  authorizationv1.SubjectAccessReviewInterface
}

func (r *roleTemplateValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("roleTemplateValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	roleTemplate, err := roleTemplateObject(request)
	if err != nil {
		return err
	}

	// object is in the process of being deleted, so admit it
	// this admits update operations that happen to remove finalizers
	if roleTemplate.DeletionTimestamp != nil {
		response.Allowed = true
		return nil
	}

	rules, err := r.roleTemplateResolver.RulesFromTemplate(roleTemplate)
	if err != nil {
		return err
	}

	// ensure all PolicyRules have at least one verb, otherwise RBAC controllers may encounter issues when creating Roles and ClusterRoles
	for i := range rules {
		if len(rules[i].Verbs) == 0 {
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

	allowed, err := auth.EscalationAuthorized(request, roleTemplateGVR, r.sar, "")
	if err != nil {
		logrus.Warnf("Failed to check for the 'escalate' verb on RoleTemplates: %v", err)
	}

	if allowed {
		response.Allowed = true
		return nil
	}

	auth.SetEscalationResponse(response, auth.ConfirmNoEscalation(request, rules, "", r.resolver))
	return nil
}

func roleTemplateObject(request *webhook.Request) (*v3.RoleTemplate, error) {
	var rt runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		rt, err = request.DecodeOldObject()
	} else {
		rt, err = request.DecodeObject()
	}
	return rt.(*v3.RoleTemplate), err
}
