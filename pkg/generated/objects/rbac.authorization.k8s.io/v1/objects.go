package v1

import (
	"encoding/json"
	"fmt"

	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/api/rbac/v1"
)

// RoleOldAndNewFromRequest gets the old and new Role objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for Role.
// Similarly, if the request is a Create operation, then the old object is the zero value for Role.
func RoleOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v1.Role, *v1.Role, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v1.Role{}
	oldObject := &v1.Role{}

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

// RoleFromRequest returns a Role object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func RoleFromRequest(request *admissionv1.AdmissionRequest) (*v1.Role, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v1.Role{}
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

// RoleBindingOldAndNewFromRequest gets the old and new RoleBinding objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for RoleBinding.
// Similarly, if the request is a Create operation, then the old object is the zero value for RoleBinding.
func RoleBindingOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v1.RoleBinding, *v1.RoleBinding, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v1.RoleBinding{}
	oldObject := &v1.RoleBinding{}

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

// RoleBindingFromRequest returns a RoleBinding object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func RoleBindingFromRequest(request *admissionv1.AdmissionRequest) (*v1.RoleBinding, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v1.RoleBinding{}
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

// ClusterRoleOldAndNewFromRequest gets the old and new ClusterRole objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for ClusterRole.
// Similarly, if the request is a Create operation, then the old object is the zero value for ClusterRole.
func ClusterRoleOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v1.ClusterRole, *v1.ClusterRole, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v1.ClusterRole{}
	oldObject := &v1.ClusterRole{}

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

// ClusterRoleFromRequest returns a ClusterRole object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func ClusterRoleFromRequest(request *admissionv1.AdmissionRequest) (*v1.ClusterRole, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v1.ClusterRole{}
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

// ClusterRoleBindingOldAndNewFromRequest gets the old and new ClusterRoleBinding objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for ClusterRoleBinding.
// Similarly, if the request is a Create operation, then the old object is the zero value for ClusterRoleBinding.
func ClusterRoleBindingOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v1.ClusterRoleBinding, *v1.ClusterRoleBinding, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v1.ClusterRoleBinding{}
	oldObject := &v1.ClusterRoleBinding{}

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

// ClusterRoleBindingFromRequest returns a ClusterRoleBinding object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func ClusterRoleBindingFromRequest(request *admissionv1.AdmissionRequest) (*v1.ClusterRoleBinding, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v1.ClusterRoleBinding{}
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
