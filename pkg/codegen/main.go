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
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

type typeInfo struct {
	Name, Type, Package string
}

func main() {
	os.Unsetenv("GOPATH")
	err := generateDocs("pkg/resources", "docs.md")
	if err != nil {
		panic(err)
	}
	controllergen.Run(args.Options{
		OutputPackage: "github.com/rancher/webhook/pkg/generated",
		Boilerplate:   "scripts/boilerplate.go.txt",
		Groups: map[string]args.Group{
			"management.cattle.io": {
				Types: []interface{}{
					v3.Cluster{},
					v3.GlobalRole{},
					v3.PodSecurityAdmissionConfigurationTemplate{},
					v3.RoleTemplate{},
					v3.ClusterRoleTemplateBinding{},
					v3.ProjectRoleTemplateBinding{},
					v3.Node{},
					v3.Feature{},
				},
			},
			"provisioning.cattle.io": {
				Types: []interface{}{
					&v1.Cluster{},
				},
			},
		},
	})

	// Generate the <TYPE>FromRequest and <TYPE>OldAndNewFromRequest functions to get the new and old objects from the webhook request.
	if err := generateObjectsFromRequest("pkg/generated/objects", map[string]args.Group{
		"management.cattle.io": {
			Types: []interface{}{
				&v3.Cluster{},
				&v3.ClusterRoleTemplateBinding{},
				&v3.Feature{},
				&v3.FleetWorkspace{},
				&v3.PodSecurityAdmissionConfigurationTemplate{},
				&v3.GlobalRole{},
				&v3.GlobalRoleBinding{},
				&v3.RoleTemplate{},
				&v3.ProjectRoleTemplateBinding{},
				&v3.NodeDriver{},
				&v3.Setting{},
			},
		},
		"provisioning.cattle.io": {
			Types: []interface{}{
				&v1.Cluster{},
			},
		},
		"core": {
			Types: []interface{}{
				&unstructured.Unstructured{},
				&corev1.Secret{},
				&corev1.Namespace{},
			},
		}}); err != nil {
		fmt.Printf("ERROR: %v\n", err)
	}
}

func generateObjectsFromRequest(outputDir string, groups map[string]args.Group) error {
	temp := template.Must(template.New("objectsFromRequest").Funcs(template.FuncMap{
		"replace": strings.ReplaceAll,
	}).Parse(objectsFromRequestTemplate))

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
	formatted, err := imports.Process(path, content, &imports.Options{FormatOnly: true, Comments: true})
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
