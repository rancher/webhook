package auth

import (
	"net/http"
	"time"

	rancherv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
	"k8s.io/utils/trace"
)

const adminRole = "admin"

func NewCRTBalidator(sar authorizationv1.SubjectAccessReviewInterface) webhook.Handler {
	return &clusterRoleTemplateBindingValidator{
		sar: sar,
	}
}

type clusterRoleTemplateBindingValidator struct {
	sar authorizationv1.SubjectAccessReviewInterface
}

func (c *clusterRoleTemplateBindingValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("clusterRoleTemplateBindingValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	crtb, err := crtbObject(request)
	if err != nil {
		return err
	}

	if crtb.ClusterName != "local" {
		response.Allowed = true
		return nil
	}

	return adminAccessCheck(c.sar, response, request)
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

func toExtra(extra map[string]authenticationv1.ExtraValue) map[string]v1.ExtraValue {
	result := map[string]v1.ExtraValue{}
	for k, v := range extra {
		result[k] = v1.ExtraValue(v)
	}
	return result
}

// adminAccessCheck checks that the user submitting the request has ** access in the local cluster
func adminAccessCheck(sar authorizationv1.SubjectAccessReviewInterface, response *webhook.Response, request *webhook.Request) error {
	resp, err := sar.Create(request.Context, &v1.SubjectAccessReview{
		Spec: v1.SubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Group:    "*",
				Verb:     "*",
				Resource: "*",
			},
			User:   request.UserInfo.Username,
			Groups: request.UserInfo.Groups,
			Extra:  toExtra(request.UserInfo.Extra),
			UID:    request.UserInfo.UID,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	if resp.Status.Allowed {
		response.Allowed = true
	} else {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: resp.Status.Reason,
			Reason:  metav1.StatusReasonUnauthorized,
			Code:    http.StatusUnauthorized,
		}
	}
	return nil
}
