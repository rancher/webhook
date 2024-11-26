package namespace

import (
	"encoding/json"
	"fmt"

	"github.com/rancher/webhook/pkg/admission"
	objectsv1 "github.com/rancher/webhook/pkg/generated/objects/core/v1"
	admissionv1 "k8s.io/api/admission/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/utils/trace"
)

const resourceLimitAnnotation = "field.cattle.io/containerDefaultResourceLimit"

type requestLimitAdmitter struct{}

// Admit ensures that the resource requests are within the limits.
func (r *requestLimitAdmitter) Admit(request *admission.Request) (*admissionv1.AdmissionResponse, error) {
	listTrace := trace.New("Namespace Admit", trace.Field{Key: "user", Value: request.UserInfo.Username})
	defer listTrace.LogIfLong(admission.SlowTraceDuration)

	switch request.Operation {
	case admissionv1.Create:
		ns, err := objectsv1.NamespaceFromRequest(&request.AdmissionRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to decode namespace from request: %w", err)
		}
		return r.admitCommonCreateUpdate(nil, ns)
	case admissionv1.Update:
		oldns, ns, err := objectsv1.NamespaceOldAndNewFromRequest(&request.AdmissionRequest)
		if err != nil {
			return nil, fmt.Errorf("failed to decode namespace from request: %w", err)
		}
		return r.admitCommonCreateUpdate(oldns, ns)
	}
	return admission.ResponseAllowed(), nil
}

type ResourceLimits struct {
	LimitsCPU      string `json:"limitsCpu"`
	LimitsMemory   string `json:"limitsMemory"`
	RequestsCPU    string `json:"requestsCpu"`
	RequestsMemory string `json:"requestsMemory"`
}

// admitCommonCreateUpdate will extract the annotation values that contain the resource limits and will call
// the validateResourceLimitsWithUnits function to determine whether or not the request is valid.
func (r *requestLimitAdmitter) admitCommonCreateUpdate(_, newNamespace *v1.Namespace) (*admissionv1.AdmissionResponse, error) {
	annotations := newNamespace.Annotations
	if annotations == nil {
		return admission.ResponseAllowed(), nil
	}

	resourceLimitJSON, exists := annotations[resourceLimitAnnotation]
	if !exists || resourceLimitJSON == "{}" {
		return admission.ResponseAllowed(), nil
	}

	var resourceLimits ResourceLimits
	if err := json.Unmarshal([]byte(resourceLimitJSON), &resourceLimits); err != nil {
		return admission.ResponseBadRequest(fmt.Sprintf("invalid resource limits annotation: %v", err)), nil
	}

	if err := validateResourceLimitsWithUnits(resourceLimits); err != nil {
		return admission.ResponseBadRequest(err.Error()), nil
	}

	return admission.ResponseAllowed(), nil
}

// validateResourceLimitsWithUnits takes a set of cpu/memory requests/limits and will return an error if the requests are
// malformed or greater than the limits.
func validateResourceLimitsWithUnits(limits ResourceLimits) error {
	requestsCPU, err := resource.ParseQuantity(limits.RequestsCPU)
	if err != nil {
		return fmt.Errorf("invalid requestsCpu value: %v", err)
	}

	limitsCPU, err := resource.ParseQuantity(limits.LimitsCPU)
	if err != nil {
		return fmt.Errorf("invalid limitsCpu value: %v", err)
	}

	if requestsCPU.Cmp(limitsCPU) > 0 {
		return fmt.Errorf("requestsCpu (%s) cannot be greater than limitsCpu (%s)", requestsCPU.String(), limitsCPU.String())
	}

	requestsMemory, err := resource.ParseQuantity(limits.RequestsMemory)
	if err != nil {
		return fmt.Errorf("invalid requestsMemory value: %v", err)
	}

	limitsMemory, err := resource.ParseQuantity(limits.LimitsMemory)
	if err != nil {
		return fmt.Errorf("invalid limitsMemory value: %v", err)
	}

	if requestsMemory.Cmp(limitsMemory) > 0 {
		return fmt.Errorf("requestsMemory (%s) cannot be greater than limitsMemory (%s)", requestsMemory.String(), limitsMemory.String())
	}

	return nil
}
