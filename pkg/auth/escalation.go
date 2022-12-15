// Package auth is holds common webhook code used during authentication
package auth

import (
	"context"
	"fmt"
	"net/http"

	"github.com/rancher/webhook/pkg/admission"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/authorization/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/user"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/kubernetes/pkg/registry/rbac/validation"
)

const (
	// CreatorIDAnn is an annotation key for the id of the creator.
	CreatorIDAnn = "field.cattle.io/creatorId"
)

// EscalationAuthorized checks if the user associated with the context is explicitly authorized to escalate the given GVR.
func EscalationAuthorized(request *admission.Request, gvr schema.GroupVersionResource, sar authorizationv1.SubjectAccessReviewInterface, namespace string) (bool, error) {
	extras := map[string]v1.ExtraValue{}
	for k, v := range request.UserInfo.Extra {
		extras[k] = v1.ExtraValue(v)
	}

	resp, err := sar.Create(request.Context, &v1.SubjectAccessReview{
		Spec: v1.SubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Verb:      "escalate",
				Namespace: namespace,
				Version:   gvr.Version,
				Resource:  gvr.Resource,
				Group:     gvr.Group,
			},
			User:   request.UserInfo.Username,
			Groups: request.UserInfo.Groups,
			Extra:  extras,
			UID:    request.UserInfo.UID,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to checkout create sar request: %w", err)
	}

	return resp.Status.Allowed, nil
}

// ConfirmNoEscalation checks that the user attempting to create a binding/role has all the permissions they are attempting
// to grant.
func ConfirmNoEscalation(request *admission.Request, rules []rbacv1.PolicyRule, namespace string, ruleResolver validation.AuthorizationRuleResolver) error {
	userInfo := &user.DefaultInfo{
		Name:   request.UserInfo.Username,
		UID:    request.UserInfo.UID,
		Groups: request.UserInfo.Groups,
		Extra:  ToExtraString(request.UserInfo.Extra),
	}

	globalCtx := k8srequest.WithNamespace(k8srequest.WithUser(context.Background(), userInfo), namespace)

	return validation.ConfirmNoEscalation(globalCtx, ruleResolver, rules)
}

// ToExtraString will convert a map of map[string]authenticationv1.ExtraValue to map[string]string.
func ToExtraString(extra map[string]authenticationv1.ExtraValue) map[string][]string {
	result := make(map[string][]string)
	for k, v := range extra {
		result[k] = v
	}
	return result
}

// SetEscalationResponse will update the given webhook response based on the provided error from an escalation request.
func SetEscalationResponse(response *admissionv1.AdmissionResponse, err error) {
	if err == nil {
		response.Allowed = true
		return
	}
	response.Result = &metav1.Status{
		Status:  "Failure",
		Message: err.Error(),
		Reason:  metav1.StatusReasonInvalid,
		Code:    http.StatusUnprocessableEntity,
	}
}
