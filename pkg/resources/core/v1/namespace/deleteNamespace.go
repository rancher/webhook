package namespace

import (
	"fmt"
	"slices"

	"github.com/rancher/webhook/pkg/admission"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/utils/trace"
)

// protectedNamespaces may not be deleted on the Rancher management (local) cluster, as removing
// them corrupts the Rancher installation. See https://github.com/rancher/rancher/issues/48303.
// The list is kept sorted because it is also used to build the webhook's namespaceSelector.
var protectedNamespaces = []string{"fleet-local", "local"}

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

	// The webhook is only registered for the protected namespaces, but the name is checked here as
	// well so that this admitter can never deny the deletion of an unrelated namespace.
	if !slices.Contains(protectedNamespaces, oldNs.Name) {
		return admission.ResponseAllowed(), nil
	}

	return admission.ResponseBadRequest(fmt.Sprintf("%q namespace may not be deleted", oldNs.Name)), nil
}
