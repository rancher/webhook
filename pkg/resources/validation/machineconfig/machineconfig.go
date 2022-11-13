package machineconfig

import (
	"time"

	"github.com/rancher/webhook/pkg/generated/objects/core/unstructured"
	"github.com/rancher/webhook/pkg/resources/validation"
	"github.com/rancher/wrangler/pkg/webhook"
	"k8s.io/utils/trace"
)

func NewMachineConfigValidator() webhook.Handler {
	return &machineConfigValidator{}
}

type machineConfigValidator struct {
}

func (p *machineConfigValidator) Admit(response *webhook.Response, request *webhook.Request) error {
	listTrace := trace.New("machineConfigValidator Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(2 * time.Second)

	oldUnstrConfig, unstrConfig, err := unstructured.UnstructuredOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return err
	}

	if response.Result = validation.CheckCreatorID(request, oldUnstrConfig, unstrConfig); response.Result != nil {
		return nil
	}

	response.Allowed = true
	return nil
}
