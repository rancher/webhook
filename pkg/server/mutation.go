package server

import (
	"net/http"

	"github.com/rancher/rancher/pkg/apis/management.cattle.io"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/rancher/pkg/apis/provisioning.cattle.io"
	v1 "github.com/rancher/rancher/pkg/apis/provisioning.cattle.io/v1"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/rancher/webhook/pkg/resources/mutation/cluster"
	"github.com/rancher/webhook/pkg/resources/mutation/fleetworkspace"
	"github.com/rancher/webhook/pkg/resources/mutation/machineconfigs"
	"github.com/rancher/webhook/pkg/resources/mutation/secret"
	"github.com/rancher/wrangler/pkg/webhook"
	k8sv1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func Mutation(client *clients.Clients) (http.Handler, error) {
	router := webhook.NewRouter()
	router.Kind("FleetWorkspace").Group(management.GroupName).Type(&v3.FleetWorkspace{}).Handle(fleetworkspace.NewMutator(client))
	router.Kind("Cluster").Group(provisioning.GroupName).Type(&v1.Cluster{}).Handle(cluster.NewMutator())
	router.Kind("Secret").Type(&k8sv1.Secret{}).Handle(secret.NewMutator())
	router.Group("rke-machine-config.cattle.io").Type(&unstructured.Unstructured{}).Handle(machineconfigs.NewMutator())
	return router, nil
}
