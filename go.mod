module github.com/rancher/webhook

go 1.14

replace k8s.io/client-go => k8s.io/client-go v0.18.0

require (
	github.com/rancher/dynamiclistener v0.2.1-0.20200910055014-8a4e63348c17
	github.com/rancher/rancher/pkg/apis v0.0.0-20200910005616-198ec5bdf52d
	github.com/rancher/wrangler v0.6.2-0.20200909050541-7465f10bdac7
	github.com/sirupsen/logrus v1.6.0
	k8s.io/api v0.18.8
	k8s.io/apimachinery v0.18.8
	k8s.io/client-go v12.0.0+incompatible
)
