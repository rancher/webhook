package main

const objectsFromRequestTemplate = `
package {{ .package }}

import (
	"encoding/json"
	"fmt"

	{{ range .types }}
	"{{ .Package }}"{{ end }}
	admissionv1 "k8s.io/api/admission/v1"
)
{{ range .types }}

// {{ .Name }}OldAndNewFromRequest gets the old and new {{ .Name }} objects, respectively, from the webhook request.
// If the request is a Delete operation, then the new object is the zero value for {{ .Name }}.
// Similarly, if the request is a Create operation, then the old object is the zero value for {{ .Name }}.
func {{ .Name }}OldAndNewFromRequest(request *admissionv1.AdmissionRequest) ({{ .Type }}, {{ .Type }}, error) {
	if request == nil {
		return nil, nil, fmt.Errorf("nil request")
	}

	object := {{ replace .Type "*" "&" }}{}
	oldObject := {{ replace .Type "*" "&" }}{}

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

// {{ .Name }}FromRequest returns a {{ .Name }} object from the webhook request.
// If the operation is a Delete operation, then the old object is returned.
// Otherwise, the new object is returned.
func {{ .Name }}FromRequest(request *admissionv1.AdmissionRequest) ({{ .Type }}, error) {
	if request == nil {
		return nil, fmt.Errorf("nil request")
	}

	object := {{ replace .Type "*" "&" }}{}
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
{{ end }}
`
