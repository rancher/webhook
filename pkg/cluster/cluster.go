package cluster

import (
	"net/http"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	authenticationv1 "k8s.io/api/authentication/v1"
	v1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	authorizationv1 "k8s.io/client-go/kubernetes/typed/authorization/v1"
)

func NewClusterValidator(sar authorizationv1.SubjectAccessReviewInterface) webhook.Handler {
	return &clusterValidator{
		sar: sar,
	}
}

type clusterValidator struct {
	sar authorizationv1.SubjectAccessReviewInterface
}

func (c *clusterValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	oldCluster, newCluster, err := clusterObjects(request)
	if err != nil {
		return err
	}

	if newCluster.Spec.FleetWorkspaceName == "" ||
		oldCluster.Spec.FleetWorkspaceName == newCluster.Spec.FleetWorkspaceName {
		response.Allowed = true
		return nil
	}

	resp, err := c.sar.Create(request.Context, &v1.SubjectAccessReview{
		Spec: v1.SubjectAccessReviewSpec{
			ResourceAttributes: &v1.ResourceAttributes{
				Verb:     "fleetaddcluster",
				Version:  "v1",
				Resource: "namespaces",
				Name:     newCluster.Spec.FleetWorkspaceName,
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

func toExtra(extra map[string]authenticationv1.ExtraValue) map[string]v1.ExtraValue {
	result := map[string]v1.ExtraValue{}
	for k, v := range extra {
		result[k] = v1.ExtraValue(v)
	}
	return result
}

func clusterObjects(request *webhook.Request) (*v3.Cluster, *v3.Cluster, error) {
	object, err := request.DecodeObject()
	if err != nil {
		return nil, nil, err
	}

	if request.Operation == admissionv1.Create {
		return &v3.Cluster{}, object.(*v3.Cluster), nil
	}

	oldObject, err := request.DecodeOldObject()
	if err != nil {
		return nil, nil, err
	}

	return oldObject.(*v3.Cluster), object.(*v3.Cluster), nil
}
