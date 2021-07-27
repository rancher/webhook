package cluster

import (
	"time"

	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/clients"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/patch"
	"github.com/rancher/wrangler/pkg/webhook"
	"k8s.io/utils/trace"
)

func NewMutator(client *clients.Clients) webhook.Handler {
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

	cluster, err := objectsv1.ClusterFromRequest(request)
	if err != nil {
		return err
	}

	newCluster := cluster.DeepCopy()

	if newCluster.Annotations == nil {
		newCluster.Annotations = make(map[string]string)
	}

	newCluster.Annotations[auth.CreatorIDAnn] = request.UserInfo.Username

	return patch.CreatePatch(cluster, newCluster, response)
}
