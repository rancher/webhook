package auth

import (
	"context"
	"fmt"
	"net/http"
	"time"

	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/authentication"
	v3 "github.com/rancher/webhook/pkg/generated/controllers/management.cattle.io/v3"
	"github.com/rancher/wrangler-api/pkg/generated/controllers/rbac"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
	rbacregistryvalidation "k8s.io/kubernetes/pkg/registry/rbac/validation"
	"k8s.io/utils/trace"
)

func NewGRBValidator(grClient v3.GlobalRoleCache, r rbac.Interface) (webhook.Handler, error) {
	rbacRestGetter := authentication.RBACRestGetter{
		Roles:               r.V1().Role().Cache(),
		RoleBindings:        r.V1().RoleBinding().Cache(),
		ClusterRoles:        r.V1().ClusterRole().Cache(),
		ClusterRoleBindings: r.V1().ClusterRoleBinding().Cache(),
	}

	ruleResolver := rbacregistryvalidation.NewDefaultRuleResolver(rbacRestGetter, rbacRestGetter, rbacRestGetter, rbacRestGetter)

	return &globalRoleBindingValidator{
		globalRoles: grClient,
		ruleSolver:  ruleResolver,
	}, nil

}

type globalRoleBindingValidator struct {
	globalRoles v3.GlobalRoleCache
	ruleSolver  validation.AuthorizationRuleResolver
}

func (grbv *globalRoleBindingValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("globalRoleBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	newGRB, err := grbObject(request)
	if err != nil {
		return err
	}

	// Pull the global role to get the rules
	globalRole, err := grbv.globalRoles.Get(newGRB.GlobalRoleName)
	if err != nil {
		return err
	}

	userInfo := &user.DefaultInfo{
		Name:   request.UserInfo.Username,
		UID:    request.UserInfo.UID,
		Groups: request.UserInfo.Groups,
		Extra:  toExtraString(request.UserInfo.Extra),
	}

	if err := grbv.ConfirmNoEscalation(globalRole.Rules, userInfo); err != nil {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: err.Error(),
			Reason:  metav1.StatusReasonUnauthorized,
			Code:    http.StatusUnauthorized,
		}
		return nil
	}
	response.Allowed = true
	return nil
}

// ConfirmNoEscalation checks that the user attempting to create the GRB has all the permissions they are attempting
// to grant through the GRB
func (grbv *globalRoleBindingValidator) ConfirmNoEscalation(rules []rbacv1.PolicyRule, userInfo *user.DefaultInfo) error {
	globaleCtx := k8srequest.WithNamespace(k8srequest.WithUser(context.Background(), userInfo), "")
	if err := rbacregistryvalidation.ConfirmNoEscalation(globaleCtx, grbv.ruleSolver, rules); err != nil {
		return fmt.Errorf("failed to validate user: %v", err)
	}
	return nil
}

func grbObject(request *webhook.Request) (*rancherv3.GlobalRoleBinding, error) {
	var grb runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		grb, err = request.DecodeOldObject()
	} else {
		grb, err = request.DecodeObject()
	}
	return grb.(*rancherv3.GlobalRoleBinding), err
}

func toExtraString(extra map[string]authenticationv1.ExtraValue) map[string][]string {
	result := make(map[string][]string)
	for k, v := range extra {
		result[k] = v
	}
	return result
}
