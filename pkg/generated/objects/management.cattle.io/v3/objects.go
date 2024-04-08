package v3

import (
	"encoding/json"
	"fmt"

	"github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	admissionv1 "k8s.io/api/admission/v1"
)

// ClusterOldAndNewFromRequest gets the old and new Cluster objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for Cluster.
// Similarly, if the request is a Create operation, then the old object is the zero value for Cluster.
func ClusterOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v3.Cluster, *v3.Cluster, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v3.Cluster{}
	oldObject := &v3.Cluster{}

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
func ClusterFromRequest(request *admissionv1.AdmissionRequest) (*v3.Cluster, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v3.Cluster{}
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

// ClusterRoleTemplateBindingOldAndNewFromRequest gets the old and new ClusterRoleTemplateBinding objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for ClusterRoleTemplateBinding.
// Similarly, if the request is a Create operation, then the old object is the zero value for ClusterRoleTemplateBinding.
func ClusterRoleTemplateBindingOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v3.ClusterRoleTemplateBinding, *v3.ClusterRoleTemplateBinding, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v3.ClusterRoleTemplateBinding{}
	oldObject := &v3.ClusterRoleTemplateBinding{}

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

// ClusterRoleTemplateBindingFromRequest returns a ClusterRoleTemplateBinding object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func ClusterRoleTemplateBindingFromRequest(request *admissionv1.AdmissionRequest) (*v3.ClusterRoleTemplateBinding, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v3.ClusterRoleTemplateBinding{}
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

// FeatureOldAndNewFromRequest gets the old and new Feature objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for Feature.
// Similarly, if the request is a Create operation, then the old object is the zero value for Feature.
func FeatureOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v3.Feature, *v3.Feature, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v3.Feature{}
	oldObject := &v3.Feature{}

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

// FeatureFromRequest returns a Feature object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func FeatureFromRequest(request *admissionv1.AdmissionRequest) (*v3.Feature, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v3.Feature{}
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

// FleetWorkspaceOldAndNewFromRequest gets the old and new FleetWorkspace objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for FleetWorkspace.
// Similarly, if the request is a Create operation, then the old object is the zero value for FleetWorkspace.
func FleetWorkspaceOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v3.FleetWorkspace, *v3.FleetWorkspace, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v3.FleetWorkspace{}
	oldObject := &v3.FleetWorkspace{}

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

// FleetWorkspaceFromRequest returns a FleetWorkspace object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func FleetWorkspaceFromRequest(request *admissionv1.AdmissionRequest) (*v3.FleetWorkspace, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v3.FleetWorkspace{}
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

// PodSecurityAdmissionConfigurationTemplateOldAndNewFromRequest gets the old and new PodSecurityAdmissionConfigurationTemplate objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for PodSecurityAdmissionConfigurationTemplate.
// Similarly, if the request is a Create operation, then the old object is the zero value for PodSecurityAdmissionConfigurationTemplate.
func PodSecurityAdmissionConfigurationTemplateOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v3.PodSecurityAdmissionConfigurationTemplate, *v3.PodSecurityAdmissionConfigurationTemplate, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v3.PodSecurityAdmissionConfigurationTemplate{}
	oldObject := &v3.PodSecurityAdmissionConfigurationTemplate{}

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

// PodSecurityAdmissionConfigurationTemplateFromRequest returns a PodSecurityAdmissionConfigurationTemplate object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func PodSecurityAdmissionConfigurationTemplateFromRequest(request *admissionv1.AdmissionRequest) (*v3.PodSecurityAdmissionConfigurationTemplate, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v3.PodSecurityAdmissionConfigurationTemplate{}
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

// GlobalRoleOldAndNewFromRequest gets the old and new GlobalRole objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for GlobalRole.
// Similarly, if the request is a Create operation, then the old object is the zero value for GlobalRole.
func GlobalRoleOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v3.GlobalRole, *v3.GlobalRole, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v3.GlobalRole{}
	oldObject := &v3.GlobalRole{}

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

// GlobalRoleFromRequest returns a GlobalRole object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func GlobalRoleFromRequest(request *admissionv1.AdmissionRequest) (*v3.GlobalRole, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v3.GlobalRole{}
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

// GlobalRoleBindingOldAndNewFromRequest gets the old and new GlobalRoleBinding objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for GlobalRoleBinding.
// Similarly, if the request is a Create operation, then the old object is the zero value for GlobalRoleBinding.
func GlobalRoleBindingOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v3.GlobalRoleBinding, *v3.GlobalRoleBinding, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v3.GlobalRoleBinding{}
	oldObject := &v3.GlobalRoleBinding{}

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

// GlobalRoleBindingFromRequest returns a GlobalRoleBinding object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func GlobalRoleBindingFromRequest(request *admissionv1.AdmissionRequest) (*v3.GlobalRoleBinding, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v3.GlobalRoleBinding{}
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

// RoleTemplateOldAndNewFromRequest gets the old and new RoleTemplate objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for RoleTemplate.
// Similarly, if the request is a Create operation, then the old object is the zero value for RoleTemplate.
func RoleTemplateOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v3.RoleTemplate, *v3.RoleTemplate, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v3.RoleTemplate{}
	oldObject := &v3.RoleTemplate{}

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

// RoleTemplateFromRequest returns a RoleTemplate object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func RoleTemplateFromRequest(request *admissionv1.AdmissionRequest) (*v3.RoleTemplate, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v3.RoleTemplate{}
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

// ProjectRoleTemplateBindingOldAndNewFromRequest gets the old and new ProjectRoleTemplateBinding objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for ProjectRoleTemplateBinding.
// Similarly, if the request is a Create operation, then the old object is the zero value for ProjectRoleTemplateBinding.
func ProjectRoleTemplateBindingOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v3.ProjectRoleTemplateBinding, *v3.ProjectRoleTemplateBinding, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v3.ProjectRoleTemplateBinding{}
	oldObject := &v3.ProjectRoleTemplateBinding{}

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

// ProjectRoleTemplateBindingFromRequest returns a ProjectRoleTemplateBinding object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func ProjectRoleTemplateBindingFromRequest(request *admissionv1.AdmissionRequest) (*v3.ProjectRoleTemplateBinding, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v3.ProjectRoleTemplateBinding{}
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

// NodeDriverOldAndNewFromRequest gets the old and new NodeDriver objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for NodeDriver.
// Similarly, if the request is a Create operation, then the old object is the zero value for NodeDriver.
func NodeDriverOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v3.NodeDriver, *v3.NodeDriver, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v3.NodeDriver{}
	oldObject := &v3.NodeDriver{}

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

// NodeDriverFromRequest returns a NodeDriver object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func NodeDriverFromRequest(request *admissionv1.AdmissionRequest) (*v3.NodeDriver, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v3.NodeDriver{}
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

// SettingOldAndNewFromRequest gets the old and new Setting objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for Setting.
// Similarly, if the request is a Create operation, then the old object is the zero value for Setting.
func SettingOldAndNewFromRequest(request *admissionv1.AdmissionRequest) (*v3.Setting, *v3.Setting, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := &v3.Setting{}
	oldObject := &v3.Setting{}

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

// SettingFromRequest returns a Setting object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func SettingFromRequest(request *admissionv1.AdmissionRequest) (*v3.Setting, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := &v3.Setting{}
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
