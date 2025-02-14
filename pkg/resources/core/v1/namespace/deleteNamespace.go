package namespace

import (
	"github.com/rancher/webhook/pkg/admission"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/utils/trace"
)

// deleteNamespaceAdmitter handles namespace deletion scenarios
type deleteNamespaceAdmitter struct{}

func (d deleteNamespaceAdmitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("Namespace Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	if request.Operation != admissionv1.Delete {
		return &admissionv1.AdmissionResponse{}, nil
	}
	return admission.ResponseBadRequest("can't delete local cluster"), nil
}
