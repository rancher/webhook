package v1

import (
	"encoding/json"
	"fmt"

	"github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	admissionv1 "k8s.io/api/admission/v1"
)

// ClusterOldAndNewFromRequest gets the old and new Cluster objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for Cluster.
// Similarly, if the request is a Create operation, then the old object is the zero value for Cluster.
func ClusterOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v1.Cluster, *v1.Cluster, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v1.Cluster{}
	oldObject := &v1.Cluster{}

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
func ClusterFromRequest(request *admissionv1.AdmissionRequest) (*v1.Cluster, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v1.Cluster{}
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
