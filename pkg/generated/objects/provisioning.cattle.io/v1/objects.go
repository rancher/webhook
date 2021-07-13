package v1

import (
	"github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

type ClusterValidationFunc func(*webhook.Request, *v1.Cluster, *v1.Cluster) (*metav1.Status, error)

func ClusterOldAndNewFromRequest(request *webhook.Request) (*v1.Cluster, *v1.Cluster, error) {
	var object runtime.Object
	var err error
	if request.Operation != admissionv1.Delete {
		object, err = request.DecodeObject()
		if err != nil {
			return nil, nil, err
		}
	} else {
		object = &v1.Cluster{}
	}

	if request.Operation == admissionv1.Create {
		return &v1.Cluster{}, object.(*v1.Cluster), nil
	}

	oldObject, err := request.DecodeOldObject()
	if err != nil {
		return nil, nil, err
	}

	return oldObject.(*v1.Cluster), object.(*v1.Cluster), nil
}

func ClusterObjectFromRequest(request *webhook.Request) (*v1.Cluster, error) {
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

	return object.(*v1.Cluster), nil
}
