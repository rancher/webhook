package secret

import (
	"fmt"

	"github.com/rancher/rancher/pkg/plan"
	"github.com/rancher/webhook/pkg/admission"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/utils/trace"
)

const machinePlanSecretType = "rke.cattle.io/machine-plan"

type planAdmitter struct{}

// Admit validates plan Secrets at admission time.
func (p *planAdmitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("secret planAdmitter Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	secret, err := objectsv1.SecretFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("unable to read secret from request: %w", err)
	}

	if secret.Type != machinePlanSecretType {
		return admission.ResponseAllowed(), nil
	}

	planData, ok := secret.Data["plan"]
	if !ok {
		return admission.ResponseAllowed(), nil
	}

	if _, err := plan.Parse(planData); err != nil {
		return admission.ResponseBadRequest(fmt.Sprintf("invalid plan: %v", err)), nil
	}

	return admission.ResponseAllowed(), nil
}
