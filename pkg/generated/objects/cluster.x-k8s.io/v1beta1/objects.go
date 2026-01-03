package v1beta1

import (
	"encoding/json"
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	"sigs.k8s.io/cluster-api/api/v1beta1"
)

// MachineDeploymentOldAndNewFromRequest gets the old and new MachineDeployment objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for MachineDeployment.
// Similarly, if the request is a Create operation, then the old object is the zero value for MachineDeployment.
func MachineDeploymentOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v1beta1.MachineDeployment, *v1beta1.MachineDeployment, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v1beta1.MachineDeployment{}
	oldObject := &v1beta1.MachineDeployment{}

	if request.Operation != admissionv1.Delete {
		err := json.Unmarshal(request.Object.Raw, object)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal request object: %w", err)
		}
	}

	if request.Operation == admissionv1.Create {
		return oldObject, object, nil
	}

	err := json.Unmarshal(request.OldObject.Raw, oldObject)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal request oldObject: %w", err)
	}

	return oldObject, object, nil
}

// MachineDeploymentFromRequest returns a MachineDeployment object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func MachineDeploymentFromRequest(request *admissionv1.AdmissionRequest) (*v1beta1.MachineDeployment, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v1beta1.MachineDeployment{}
	raw := request.Object.Raw

	if request.Operation == admissionv1.Delete {
		raw = request.OldObject.Raw
	}

	err := json.Unmarshal(raw, object)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal request object: %w", err)
	}

	return object, nil
}

// ClusterOldAndNewFromRequest gets the old and new Cluster objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for Cluster.
// Similarly, if the request is a Create operation, then the old object is the zero value for Cluster.
func ClusterOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v1beta1.Cluster, *v1beta1.Cluster, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v1beta1.Cluster{}
	oldObject := &v1beta1.Cluster{}

	if request.Operation != admissionv1.Delete {
		err := json.Unmarshal(request.Object.Raw, object)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal request object: %w", err)
		}
	}

	if request.Operation == admissionv1.Create {
		return oldObject, object, nil
	}

	err := json.Unmarshal(request.OldObject.Raw, oldObject)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal request oldObject: %w", err)
	}

	return oldObject, object, nil
}

// ClusterFromRequest returns a Cluster object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func ClusterFromRequest(request *admissionv1.AdmissionRequest) (*v1beta1.Cluster, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v1beta1.Cluster{}
	raw := request.Object.Raw

	if request.Operation == admissionv1.Delete {
		raw = request.OldObject.Raw
	}

	err := json.Unmarshal(raw, object)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal request object: %w", err)
	}

	return object, nil
}
