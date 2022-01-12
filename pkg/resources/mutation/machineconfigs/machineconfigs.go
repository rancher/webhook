package machineconfigs

import (
	"time"

	"github.com/rancher/webhook/pkg/generated/objects/core/unstructured"
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

	listTrace := trace.New("machine config Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	config, err := unstructured.UnstructuredFromRequest(request)
	if err != nil {
		return err
	}

	return mutation.SetCreatorIDAnnotation(request, response, config, config.DeepCopy())
}
