package cluster

import (
	"fmt"
	"time"

	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/resources/mutation"
	"github.com/rancher/wrangler/pkg/webhook"
	"k8s.io/utils/trace"
)

func NewMutator() webhook.Handler {
	return &mutator{}
}

type mutator struct {
}

func (m *mutator) Admit(response *webhook.Response, request *webhook.Request) error {
	if request.DryRun != nil && *request.DryRun {
		response.Allowed = true
		return nil
	}

	listTrace := trace.New("provisioningCluster Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	cluster, err := objectsv1.ClusterFromRequest(&request.AdmissionRequest)
	if err != nil {
		return err
	}
	if err := mutation.SetCreatorIDAnnotation(request, response, request.Object, cluster.DeepCopy()); err != nil {
		return fmt.Errorf("failed to set creatorIDAnnotation: %w", err)
	}
	response.Allowed = true
	return nil
}
