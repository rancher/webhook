package cluster

import (
	"net/http"
	"time"

	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/auth"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/provisioning.cattle.io/v1"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/trace"
)

// The validator functions to call for v1.Clusters requests
var v1ClusterValidators = []objectsv1.ClusterValidationFunc{validateCreatorID, validateACEConfig}

func NewProvisioningClusterValidator() webhook.Handler {
	return &provisioningClusterValidator{}
}

type provisioningClusterValidator struct{}

func (p *provisioningClusterValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("provisioningClusterValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)
	oldCluster, cluster, err := objectsv1.ClusterOldAndNewFromRequest(request)
	if err != nil {
		return err
	}

	for _, validator := range v1ClusterValidators {
		if status, err := validator(request, oldCluster, cluster); err != nil {
			return err
		} else if status != nil {
			response.Result = status
			return nil
		}
	}

	response.Allowed = true
	return nil
}

func validateCreatorID(request *webhook.Request, oldCluster, cluster *v1.Cluster) (*metav1.Status, error) {
	status := &metav1.Status{
		Status: "Failure",
		Reason: metav1.StatusReasonInvalid,
		Code:   http.StatusUnprocessableEntity,
	}

	if request.Operation == admissionv1.Create {
		// When creating the cluster the annotation must match the user creating it
		if cluster.Annotations[auth.CreatorIDAnn] != request.UserInfo.Username {
			status.Message = "creatorID annotation does not match user"
			return status, nil
		}
		return nil, nil
	}

	// Check that the anno doesn't exist on the update object, the only allowed
	// update to this field is deleting it.
	if _, ok := cluster.Annotations[auth.CreatorIDAnn]; !ok {
		return nil, nil
	}

	// Compare old vs new because they need to be the same, no updates are allowed for
	// the CreatorIDAnn
	if oldCluster.GetAnnotations()[auth.CreatorIDAnn] != cluster.GetAnnotations()[auth.CreatorIDAnn] {
		status.Message = "creatorID annotation cannot be changed"
		return status, nil
	}

	return nil, nil
}

func validateACEConfig(_ *webhook.Request, _, cluster *v1.Cluster) (*metav1.Status, error) {
	if cluster.Spec.RKEConfig.LocalClusterAuthEndpoint.Enabled && cluster.Spec.RKEConfig.LocalClusterAuthEndpoint.CACerts != "" && cluster.Spec.RKEConfig.LocalClusterAuthEndpoint.FQDN == "" {
		return &metav1.Status{
			Status:  "Failure",
			Message: "CACerts defined by FQDN is not defined",
			Reason:  metav1.StatusReasonInvalid,
			Code:    http.StatusUnprocessableEntity,
		}, nil
	}

	return nil, nil
}
