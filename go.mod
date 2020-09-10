module github.com/rancher/webhook

go 1.14

replace k8s.io/client-go => k8s.io/client-go v0.18.0

require (
	github.com/rancher/dynamiclistener v0.2.1-0.20200811000611-30cb223867a4
	github.com/rancher/rancher/pkg/apis v0.0.0
	github.com/rancher/wrangler v0.6.2-0.20200829053106-7e1dd4260224
	github.com/sirupsen/logrus v1.6.0
	k8s.io/api v0.18.8
	k8s.io/apimachinery v0.18.8
	k8s.io/client-go v12.0.0+incompatible
)

replace github.com/rancher/wrangler => ../wrangler

replace github.com/rancher/rancher/pkg/apis => ../rancher/pkg/apis
