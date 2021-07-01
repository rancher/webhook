package cluster

import (
	"net/http"
	"time"

	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/trace"
)

func NewProvisioningClusterValidator() webhook.Handler {
	return &provisioningClusterValidator{}
}

type provisioningClusterValidator struct{}

func (p *provisioningClusterValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("provisioningClusterValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)
	cluster, err := clusterObject(request)
	if err != nil {
		return err
	}

	if request.Operation == admissionv1.Create {
		// When creating the cluster the annotation must match the user creating it
		if cluster.Annotations[auth.CreatorIDAnn] != request.UserInfo.Username {
			response.Result = &metav1.Status{
				Status:  "Failure",
				Message: "creatorID annotation does not match user",
				Reason:  metav1.StatusReasonInvalid,
				Code:    http.StatusUnprocessableEntity,
			}
			return nil
		}
		response.Allowed = true
		return nil
	}

	// Check that the anno doesn't exist on the update object, the only allowed
	// update to this field is deleting it.
	if _, ok := cluster.Annotations[auth.CreatorIDAnn]; !ok {
		response.Allowed = true
		return nil
	}

	c, err := request.DecodeOldObject()
	if err != nil {
		return err
	}

	oldCluster := c.(*v1.Cluster)

	// Compare old vs new because they need to be the same, no updates are allowed for
	// the CreatorIDAnn
	if oldCluster.GetAnnotations()[auth.CreatorIDAnn] != cluster.GetAnnotations()[auth.CreatorIDAnn] {
		response.Result = &metav1.Status{
			Status:  "Failure",
			Message: "creatorID annotation cannot be changed",
			Reason:  metav1.StatusReasonInvalid,
			Code:    http.StatusUnprocessableEntity,
		}
		return nil
	}

	response.Allowed = true
	return nil
}

func clusterObject(request *webhook.Request) (*v1.Cluster, error) {
	var cluster runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		cluster, err = request.DecodeOldObject()
	} else {
		cluster, err = request.DecodeObject()
	}
	return cluster.(*v1.Cluster), err
}
