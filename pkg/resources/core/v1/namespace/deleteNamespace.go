package namespace

import (
	"fmt"

	"github.com/rancher/webhook/pkg/admission"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/utils/trace"
)

// deleteNamespaceAdmitter handles namespace deletion scenarios
type deleteNamespaceAdmitter struct{}

func (d deleteNamespaceAdmitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("Namespace Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	if request.Operation != admissionv1.Delete {
		return admission.ResponseAllowed(), nil
	}

	oldNs, _, err := objectsv1.NamespaceOldAndNewFromRequest(&request.AdmissionRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to decode namespace from request: %w", err)
	}

	return admission.ResponseBadRequest(fmt.Sprintf("%q namespace my not be deleted\n", oldNs.Name)), nil
}
