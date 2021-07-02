package cluster

import (
	"time"

	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/auth"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/rancher/webhook/pkg/patch"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
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

	cluster, err := clusterObject(request)
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
