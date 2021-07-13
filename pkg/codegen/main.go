package main

import (
	"bytes"
	"fmt"
	"os"
	"path"
	"reflect"
	"strings"
	"text/template"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	controllergen "github.com/rancher/wrangler/pkg/controller-gen"
	"github.com/rancher/wrangler/pkg/controller-gen/args"
	"golang.org/x/tools/imports"
)

const objectFromRequestTemplate = `
package {{ .package }}

import (
	{{ range .types }}
	"{{ .Package }}"{{ end }}
	"github.com/rancher/wrangler/pkg/webhook"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)
{{ range .types }}

type {{ .Name }}ValidationFunc func(*webhook.Request, {{ .Type }}, {{ .Type }}) (*metav1.Status, error)

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

func {{ .Name }}ObjectFromRequest(request *webhook.Request) ({{ .Type }}, error) {
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

type typeInfo struct {
	Name, Type, Package string
}

func main() {
	os.Unsetenv("GOPATH")
	controllergen.Run(args.Options{
		OutputPackage: "github.com/rancher/webhook/pkg/generated",
		Boilerplate:   "scripts/boilerplate.go.txt",
		Groups: map[string]args.Group{
			"management.cattle.io": {
				Types: []interface{}{
					v3.Cluster{},
					v3.GlobalRole{},
					v3.RoleTemplate{},
				},
			},
		},
	})

	// Generate the <TYPE>ObjectsFromRequest functions to get the new and old objects from the webhook request.
	if err := generateObjectsFromRequest("pkg/generated/objects", map[string]args.Group{
		"management.cattle.io": {
			Types: []interface{}{
				&v3.Cluster{},
				&v3.ClusterRoleTemplateBinding{},
				&v3.FleetWorkspace{},
				&v3.GlobalRole{},
				&v3.GlobalRoleBinding{},
				&v3.RoleTemplate{},
				&v3.ProjectRoleTemplateBinding{},
			},
		},
		"provisioning.cattle.io": {
			Types: []interface{}{
				&v1.Cluster{},
			},
		}}); err != nil {
		fmt.Printf("ERROR: %v\n", err)
	}
}

func generateObjectsFromRequest(outputDir string, groups map[string]args.Group) error {
	temp := template.Must(template.New("objectsFromRequest").Funcs(template.FuncMap{
		"replace": strings.ReplaceAll,
	}).Parse(objectFromRequestTemplate))

	for groupName, group := range groups {
		var packageName string
		types := make([]typeInfo, 0, len(group.Types))

		for _, t := range group.Types {
			rt := reflect.TypeOf(t)
			ti := typeInfo{
				Type: rt.String(),
			}
			if rt.Kind() == reflect.Ptr {
				// PkgPath returns an empty string for pointers
				// Elem returns a Type associated to the dereferenced type.
				rt = rt.Elem()
			}
			ti.Package = rt.PkgPath()
			ti.Name = rt.Name()
			packageName = path.Base(ti.Package)
			types = append(types, ti)
		}

		groupDir := path.Join(outputDir, groupName, packageName)
		if err := os.MkdirAll(groupDir, 0755); err != nil {
			return err
		}

		data := map[string]interface{}{
			"types":   types,
			"package": packageName,
		}

		var content bytes.Buffer
		if err := temp.Execute(&content, data); err != nil {
			return err
		}

		if err := gofmtAndWriteToFile(path.Join(groupDir, "objects.go"), content.Bytes()); err != nil {
			return err
		}
	}

	return nil
}

func gofmtAndWriteToFile(path string, content []byte) error {
	formatted, err := imports.Process(path, content, &imports.Options{FormatOnly: true})
	if err != nil {
		return err
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.Write(formatted)
	return err
}
