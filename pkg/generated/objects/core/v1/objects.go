package v1

import (
	"encoding/json"
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// UnstructuredOldAndNewFromRequest gets the old and new Unstructured objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for Unstructured.
// Similarly, if the request is a Create operation, then the old object is the zero value for Unstructured.
func UnstructuredOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*unstructured.Unstructured, *unstructured.Unstructured, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &unstructured.Unstructured{}
	oldObject := &unstructured.Unstructured{}

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

// UnstructuredFromRequest returns a Unstructured object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func UnstructuredFromRequest(request *admissionv1.AdmissionRequest) (*unstructured.Unstructured, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &unstructured.Unstructured{}
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

// SecretOldAndNewFromRequest gets the old and new Secret objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for Secret.
// Similarly, if the request is a Create operation, then the old object is the zero value for Secret.
func SecretOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v1.Secret, *v1.Secret, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v1.Secret{}
	oldObject := &v1.Secret{}

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

// SecretFromRequest returns a Secret object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func SecretFromRequest(request *admissionv1.AdmissionRequest) (*v1.Secret, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v1.Secret{}
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
