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
	"github.com/rancher/webhook/pkg/resources/mutation/secret"
	"github.com/rancher/wrangler/pkg/webhook"
	k8sv1 "k8s.io/api/core/v1"
)

func Mutation(client *clients.Clients) (http.Handler, error) {
	fleetworkspaceMutator := fleetworkspace.NewMutator(client)
	provisioningCluster := cluster.NewMutator(client)
	secret := secret.NewMutator()

	router := webhook.NewRouter()
	router.Kind("FleetWorkspace").Group(management.GroupName).Type(&v3.FleetWorkspace{}).Handle(fleetworkspaceMutator)
	router.Kind("Cluster").Group(provisioning.GroupName).Type(&v1.Cluster{}).Handle(provisioningCluster)
	router.Kind("Secret").Group("").Type(&k8sv1.Secret{}).Handle(secret)
	return router, nil
}
