package main

const objectsFromRequestTemplate = `
package {{ .package }}

import (
	{{ range .types }}
	"{{ .Package }}"{{ end }}
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	"k8s.io/apimachinery/pkg/runtime"
)
{{ range .types }}

// {{ .Name }}OldAndNewFromRequest gets the old and new {{ .Name }} objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for {{ .Name }}.
// Similarly, if the request is a Create operation, then the old object is the zero value for {{ .Name }}.
func {{ .Name }}OldAndNewFromRequest(request *webhook.Request) ({{ .Type }}, {{ .Type }}, error) {
	var object runtime.Object
	var err error
	if request.Operation != admissionv1.Delete {
		object, err = request.DecodeObject()
		if err != nil {
			return nil, nil, err
		}
	} else {
		object = {{ replace .Type "*" "&" }}{}
	}

	if request.Operation == admissionv1.Create {
		return {{ replace .Type "*" "&" }}{}, object.({{ .Type }}), nil
	}

	oldObject, err := request.DecodeOldObject()
	if err != nil {
		return nil, nil, err
	}

	return oldObject.({{ .Type }}), object.({{ .Type }}), nil
}

// {{ .Name }}FromRequest returns a {{ .Name }} object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func {{ .Name }}FromRequest(request *webhook.Request) ({{ .Type }}, error) {
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

	return object.({{ .Type }}), nil
}
{{ end }}
`
