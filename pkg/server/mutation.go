package server

import (
	"net/http"

	"github.com/rancher/rancher/pkg/apis/management.cattle.io"
	v3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	"github.com/rancher/webhook/pkg/clients"
	"github.com/rancher/webhook/pkg/resources/fleetworkspace"
	"github.com/rancher/wrangler/pkg/webhook"
)

func Mutation(client *clients.Clients) (http.Handler, error) {
	fleetworkspaceMutator := fleetworkspace.NewMutator(client)

	router := webhook.NewRouter()
	router.Kind("FleetWorkspace").Group(management.GroupName).Type(&v3.FleetWorkspace{}).Handle(fleetworkspaceMutator)
	return router, nil
}
