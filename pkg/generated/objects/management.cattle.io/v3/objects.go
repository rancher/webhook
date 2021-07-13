package v3

import (
	"github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type ClusterValidationFunc func(*webhook.Request, *v3.Cluster, *v3.Cluster) (*metav1.Status, error)

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

func ClusterObjectFromRequest(request *webhook.Request) (*v3.Cluster, error) {
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

type ClusterRoleTemplateBindingValidationFunc func(*webhook.Request, *v3.ClusterRoleTemplateBinding, *v3.ClusterRoleTemplateBinding) (*metav1.Status, error)

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

func ClusterRoleTemplateBindingObjectFromRequest(request *webhook.Request) (*v3.ClusterRoleTemplateBinding, error) {
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

type FleetWorkspaceValidationFunc func(*webhook.Request, *v3.FleetWorkspace, *v3.FleetWorkspace) (*metav1.Status, error)

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

func FleetWorkspaceObjectFromRequest(request *webhook.Request) (*v3.FleetWorkspace, error) {
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

type GlobalRoleValidationFunc func(*webhook.Request, *v3.GlobalRole, *v3.GlobalRole) (*metav1.Status, error)

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

func GlobalRoleObjectFromRequest(request *webhook.Request) (*v3.GlobalRole, error) {
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

type GlobalRoleBindingValidationFunc func(*webhook.Request, *v3.GlobalRoleBinding, *v3.GlobalRoleBinding) (*metav1.Status, error)

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

func GlobalRoleBindingObjectFromRequest(request *webhook.Request) (*v3.GlobalRoleBinding, error) {
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

type RoleTemplateValidationFunc func(*webhook.Request, *v3.RoleTemplate, *v3.RoleTemplate) (*metav1.Status, error)

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

func RoleTemplateObjectFromRequest(request *webhook.Request) (*v3.RoleTemplate, error) {
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

type ProjectRoleTemplateBindingValidationFunc func(*webhook.Request, *v3.ProjectRoleTemplateBinding, *v3.ProjectRoleTemplateBinding) (*metav1.Status, error)

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

func ProjectRoleTemplateBindingObjectFromRequest(request *webhook.Request) (*v3.ProjectRoleTemplateBinding, error) {
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
