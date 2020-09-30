package main

import (
	"os"

	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	controllergen "github.com/rancher/wrangler/pkg/controller-gen"
	"github.com/rancher/wrangler/pkg/controller-gen/args"
	v1 "k8s.io/api/rbac/v1"
)

func main() {
	os.Unsetenv("GOPATH")
	controllergen.Run(args.Options{
		OutputPackage: "github.com/rancher/webhook/pkg/generated",
		Boilerplate:   "scripts/boilerplate.go.txt",
		Groups: map[string]args.Group{
			"management.cattle.io": {
				Types: []interface{}{
					v3.GlobalRole{},
					v3.RoleTemplate{},
				},
			},
			"rbac.authorization.k8s.io": {
				Types: []interface{}{
					v1.ClusterRole{},
				},
			},
		},
	})
}
