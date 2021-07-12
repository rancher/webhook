package v3

import (
	"github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// ClusterOldAndNewFromRequest gets the old and new Cluster objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for Cluster.
// Similarly, if the request is a Create operation, then the old object is the zero value for Cluster.
func ClusterOldAndNewFromRequest(request *webhook.Request) (*v3.Cluster, *v3.Cluster, error) {
	var object runtime.Object
	var err error
	if request.Operation != admissionv1.Delete {
		object, err = request.DecodeObject()
		if err != nil {
			return nil, nil, err
		}
	} else {
		object = &v3.Cluster{}
	}

	if request.Operation == admissionv1.Create {
		return &v3.Cluster{}, object.(*v3.Cluster), nil
	}

	oldObject, err := request.DecodeOldObject()
	if err != nil {
		return nil, nil, err
	}

	return oldObject.(*v3.Cluster), object.(*v3.Cluster), nil
}

// ClusterFromRequest returns a Cluster object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func ClusterFromRequest(request *webhook.Request) (*v3.Cluster, error) {
	var object runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		object, err = request.DecodeOldObject()
	} else {
		object, err = request.DecodeObject()
	}

	if err != nil {
		return nil, err
	}

	return object.(*v3.Cluster), nil
}

// ClusterRoleTemplateBindingOldAndNewFromRequest gets the old and new ClusterRoleTemplateBinding objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for ClusterRoleTemplateBinding.
// Similarly, if the request is a Create operation, then the old object is the zero value for ClusterRoleTemplateBinding.
func ClusterRoleTemplateBindingOldAndNewFromRequest(request *webhook.Request) (*v3.ClusterRoleTemplateBinding, *v3.ClusterRoleTemplateBinding, error) {
	var object runtime.Object
	var err error
	if request.Operation != admissionv1.Delete {
		object, err = request.DecodeObject()
		if err != nil {
			return nil, nil, err
		}
	} else {
		object = &v3.ClusterRoleTemplateBinding{}
	}

	if request.Operation == admissionv1.Create {
		return &v3.ClusterRoleTemplateBinding{}, object.(*v3.ClusterRoleTemplateBinding), nil
	}

	oldObject, err := request.DecodeOldObject()
	if err != nil {
		return nil, nil, err
	}

	return oldObject.(*v3.ClusterRoleTemplateBinding), object.(*v3.ClusterRoleTemplateBinding), nil
}

// ClusterRoleTemplateBindingFromRequest returns a ClusterRoleTemplateBinding object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func ClusterRoleTemplateBindingFromRequest(request *webhook.Request) (*v3.ClusterRoleTemplateBinding, error) {
	var object runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		object, err = request.DecodeOldObject()
	} else {
		object, err = request.DecodeObject()
	}

	if err != nil {
		return nil, err
	}

	return object.(*v3.ClusterRoleTemplateBinding), nil
}

// FleetWorkspaceOldAndNewFromRequest gets the old and new FleetWorkspace objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for FleetWorkspace.
// Similarly, if the request is a Create operation, then the old object is the zero value for FleetWorkspace.
func FleetWorkspaceOldAndNewFromRequest(request *webhook.Request) (*v3.FleetWorkspace, *v3.FleetWorkspace, error) {
	var object runtime.Object
	var err error
	if request.Operation != admissionv1.Delete {
		object, err = request.DecodeObject()
		if err != nil {
			return nil, nil, err
		}
	} else {
		object = &v3.FleetWorkspace{}
	}

	if request.Operation == admissionv1.Create {
		return &v3.FleetWorkspace{}, object.(*v3.FleetWorkspace), nil
	}

	oldObject, err := request.DecodeOldObject()
	if err != nil {
		return nil, nil, err
	}

	return oldObject.(*v3.FleetWorkspace), object.(*v3.FleetWorkspace), nil
}

// FleetWorkspaceFromRequest returns a FleetWorkspace object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func FleetWorkspaceFromRequest(request *webhook.Request) (*v3.FleetWorkspace, error) {
	var object runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		object, err = request.DecodeOldObject()
	} else {
		object, err = request.DecodeObject()
	}

	if err != nil {
		return nil, err
	}

	return object.(*v3.FleetWorkspace), nil
}

// GlobalRoleOldAndNewFromRequest gets the old and new GlobalRole objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for GlobalRole.
// Similarly, if the request is a Create operation, then the old object is the zero value for GlobalRole.
func GlobalRoleOldAndNewFromRequest(request *webhook.Request) (*v3.GlobalRole, *v3.GlobalRole, error) {
	var object runtime.Object
	var err error
	if request.Operation != admissionv1.Delete {
		object, err = request.DecodeObject()
		if err != nil {
			return nil, nil, err
		}
	} else {
		object = &v3.GlobalRole{}
	}

	if request.Operation == admissionv1.Create {
		return &v3.GlobalRole{}, object.(*v3.GlobalRole), nil
	}

	oldObject, err := request.DecodeOldObject()
	if err != nil {
		return nil, nil, err
	}

	return oldObject.(*v3.GlobalRole), object.(*v3.GlobalRole), nil
}

// GlobalRoleFromRequest returns a GlobalRole object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func GlobalRoleFromRequest(request *webhook.Request) (*v3.GlobalRole, error) {
	var object runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		object, err = request.DecodeOldObject()
	} else {
		object, err = request.DecodeObject()
	}

	if err != nil {
		return nil, err
	}

	return object.(*v3.GlobalRole), nil
}

// GlobalRoleBindingOldAndNewFromRequest gets the old and new GlobalRoleBinding objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for GlobalRoleBinding.
// Similarly, if the request is a Create operation, then the old object is the zero value for GlobalRoleBinding.
func GlobalRoleBindingOldAndNewFromRequest(request *webhook.Request) (*v3.GlobalRoleBinding, *v3.GlobalRoleBinding, error) {
	var object runtime.Object
	var err error
	if request.Operation != admissionv1.Delete {
		object, err = request.DecodeObject()
		if err != nil {
			return nil, nil, err
		}
	} else {
		object = &v3.GlobalRoleBinding{}
	}

	if request.Operation == admissionv1.Create {
		return &v3.GlobalRoleBinding{}, object.(*v3.GlobalRoleBinding), nil
	}

	oldObject, err := request.DecodeOldObject()
	if err != nil {
		return nil, nil, err
	}

	return oldObject.(*v3.GlobalRoleBinding), object.(*v3.GlobalRoleBinding), nil
}

// GlobalRoleBindingFromRequest returns a GlobalRoleBinding object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func GlobalRoleBindingFromRequest(request *webhook.Request) (*v3.GlobalRoleBinding, error) {
	var object runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		object, err = request.DecodeOldObject()
	} else {
		object, err = request.DecodeObject()
	}

	if err != nil {
		return nil, err
	}

	return object.(*v3.GlobalRoleBinding), nil
}

// RoleTemplateOldAndNewFromRequest gets the old and new RoleTemplate objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for RoleTemplate.
// Similarly, if the request is a Create operation, then the old object is the zero value for RoleTemplate.
func RoleTemplateOldAndNewFromRequest(request *webhook.Request) (*v3.RoleTemplate, *v3.RoleTemplate, error) {
	var object runtime.Object
	var err error
	if request.Operation != admissionv1.Delete {
		object, err = request.DecodeObject()
		if err != nil {
			return nil, nil, err
		}
	} else {
		object = &v3.RoleTemplate{}
	}

	if request.Operation == admissionv1.Create {
		return &v3.RoleTemplate{}, object.(*v3.RoleTemplate), nil
	}

	oldObject, err := request.DecodeOldObject()
	if err != nil {
		return nil, nil, err
	}

	return oldObject.(*v3.RoleTemplate), object.(*v3.RoleTemplate), nil
}

// RoleTemplateFromRequest returns a RoleTemplate object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func RoleTemplateFromRequest(request *webhook.Request) (*v3.RoleTemplate, error) {
	var object runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		object, err = request.DecodeOldObject()
	} else {
		object, err = request.DecodeObject()
	}

	if err != nil {
		return nil, err
	}

	return object.(*v3.RoleTemplate), nil
}

// ProjectRoleTemplateBindingOldAndNewFromRequest gets the old and new ProjectRoleTemplateBinding objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for ProjectRoleTemplateBinding.
// Similarly, if the request is a Create operation, then the old object is the zero value for ProjectRoleTemplateBinding.
func ProjectRoleTemplateBindingOldAndNewFromRequest(request *webhook.Request) (*v3.ProjectRoleTemplateBinding, *v3.ProjectRoleTemplateBinding, error) {
	var object runtime.Object
	var err error
	if request.Operation != admissionv1.Delete {
		object, err = request.DecodeObject()
		if err != nil {
			return nil, nil, err
		}
	} else {
		object = &v3.ProjectRoleTemplateBinding{}
	}

	if request.Operation == admissionv1.Create {
		return &v3.ProjectRoleTemplateBinding{}, object.(*v3.ProjectRoleTemplateBinding), nil
	}

	oldObject, err := request.DecodeOldObject()
	if err != nil {
		return nil, nil, err
	}

	return oldObject.(*v3.ProjectRoleTemplateBinding), object.(*v3.ProjectRoleTemplateBinding), nil
}

// ProjectRoleTemplateBindingFromRequest returns a ProjectRoleTemplateBinding object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func ProjectRoleTemplateBindingFromRequest(request *webhook.Request) (*v3.ProjectRoleTemplateBinding, error) {
	var object runtime.Object
	var err error
	if request.Operation == admissionv1.Delete {
		object, err = request.DecodeOldObject()
	} else {
		object, err = request.DecodeObject()
	}

	if err != nil {
		return nil, err
	}

	return object.(*v3.ProjectRoleTemplateBinding), nil
}
