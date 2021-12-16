package unstructured

import (
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// UnstructuredOldAndNewFromRequest gets the old and new Unstructured objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for Unstructured.
// Similarly, if the request is a Create operation, then the old object is the zero value for Unstructured.
func UnstructuredOldAndNewFromRequest(request *webhook.Request) (*unstructured.Unstructured, *unstructured.Unstructured, error) {
	var object runtime.Object
	var err error
	if request.Operation != admissionv1.Delete {
		object, err = request.DecodeObject()
		if err != nil {
			return nil, nil, err
		}
	} else {
		object = &unstructured.Unstructured{}
	}

	if request.Operation == admissionv1.Create {
		return &unstructured.Unstructured{}, object.(*unstructured.Unstructured), nil
	}

	oldObject, err := request.DecodeOldObject()
	if err != nil {
		return nil, nil, err
	}

	return oldObject.(*unstructured.Unstructured), object.(*unstructured.Unstructured), nil
}

// UnstructuredFromRequest returns a Unstructured object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func UnstructuredFromRequest(request *webhook.Request) (*unstructured.Unstructured, error) {
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

	return object.(*unstructured.Unstructured), nil
}
