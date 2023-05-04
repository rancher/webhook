module github.com/rancher/webhook

go 1.19

replace (
	k8s.io/api => k8s.io/api v0.25.5
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.25.5
	k8s.io/apimachinery => k8s.io/apimachinery v0.25.5
	k8s.io/apiserver => k8s.io/apiserver v0.25.5
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.25.5
	k8s.io/client-go => github.com/rancher/client-go v1.25.4-rancher1
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.25.5
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.25.5
	k8s.io/code-generator => k8s.io/code-generator v0.25.5
	k8s.io/component-base => k8s.io/component-base v0.25.5
	k8s.io/component-helpers => k8s.io/component-helpers v0.25.5
	k8s.io/controller-manager => k8s.io/controller-manager v0.25.5
	k8s.io/cri-api => k8s.io/cri-api v0.25.5
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.25.5
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.25.5
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.25.5
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.25.5
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.25.5
	k8s.io/kubectl => k8s.io/kubectl v0.25.5
	k8s.io/kubelet => k8s.io/kubelet v0.25.5
	k8s.io/kubernetes => k8s.io/kubernetes v1.24.5
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.25.5
	k8s.io/metrics => k8s.io/metrics v0.25.5
	k8s.io/mount-utils => k8s.io/mount-utils v0.25.5
	k8s.io/pod-security-admission => k8s.io/pod-security-admission v0.25.5
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.25.5
)

require (
	github.com/blang/semver v3.5.1+incompatible
	github.com/golang/mock v1.6.0
	github.com/gorilla/mux v1.8.0
	github.com/rancher/dynamiclistener v0.3.5
	github.com/rancher/lasso v0.0.0-20221227210133-6ea88ca2fbcc
	github.com/rancher/lasso/controller-runtime v0.0.0-20221206162308-10123d5719ad
	github.com/rancher/rancher/pkg/apis v0.0.0-20230503225719-6e9989c790fe
	github.com/rancher/rke v1.4.6-rc1
	github.com/rancher/wrangler v1.1.1
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.2
	golang.org/x/exp v0.0.0-20230206171751-46f607a40771
	golang.org/x/tools v0.7.0
	k8s.io/api v0.25.5
	k8s.io/apiextensions-apiserver v0.25.5
	k8s.io/apimachinery v0.25.5
	k8s.io/apiserver v0.25.5
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/kubernetes v1.25.4
	k8s.io/pod-security-admission v0.25.4
	k8s.io/utils v0.0.0-20221011040102-427025108f67
	sigs.k8s.io/cluster-api v1.2.8
	sigs.k8s.io/controller-runtime v0.12.3
	sigs.k8s.io/yaml v1.3.0
)

require (
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.2.0 // indirect
	github.com/Masterminds/sprig/v3 v3.2.3 // indirect
	github.com/PuerkitoBio/purell v1.1.1 // indirect
	github.com/PuerkitoBio/urlesc v0.0.0-20170810143723-de5bf2ad4578 // indirect
	github.com/antlr/antlr4/runtime/Go/antlr v0.0.0-20220418222510-f25a4f6275ed // indirect
	github.com/asaskevich/govalidator v0.0.0-20190424111038-f61b66f89f4a // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/emicklei/go-restful/v3 v3.10.1 // indirect
	github.com/evanphx/json-patch v4.12.0+incompatible // indirect
	github.com/fsnotify/fsnotify v1.5.4 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-openapi/jsonpointer v0.19.5 // indirect
	github.com/go-openapi/jsonreference v0.19.5 // indirect
	github.com/go-openapi/swag v0.19.14 // indirect
	github.com/gobuffalo/flect v0.2.5 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/cel-go v0.12.5 // indirect
	github.com/google/gnostic v0.5.7-v3refs // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/huandu/xstrings v1.3.3 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mailru/easyjson v0.7.6 // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/onsi/gomega v1.27.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_golang v1.12.1 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.32.1 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/rancher/aks-operator v1.1.0 // indirect
	github.com/rancher/eks-operator v1.2.0 // indirect
	github.com/rancher/fleet/pkg/apis v0.0.0-20230420151154-ab055fa31e05 // indirect
	github.com/rancher/gke-operator v1.1.5 // indirect
	github.com/rancher/norman v0.0.0-20230328153514-ae12f166495a // indirect
	github.com/shopspring/decimal v1.2.0 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	golang.org/x/crypto v0.3.0 // indirect
	golang.org/x/mod v0.9.0 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/oauth2 v0.0.0-20220608161450-d0670ef3b1eb // indirect
	golang.org/x/sync v0.1.0 // indirect
	golang.org/x/sys v0.6.0 // indirect
	golang.org/x/term v0.6.0 // indirect
	golang.org/x/text v0.8.0 // indirect
	golang.org/x/time v0.0.0-20220210224613-90d013bbcef8 // indirect
	gomodules.xyz/jsonpatch/v2 v2.2.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20220714211235-042d03aeabc9 // indirect
	google.golang.org/protobuf v1.28.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/code-generator v0.25.5 // indirect
	k8s.io/component-base v0.25.5 // indirect
	k8s.io/component-helpers v0.25.5 // indirect
	k8s.io/gengo v0.0.0-20211129171323-c02415ce4185 // indirect
	k8s.io/klog v1.0.0 // indirect
	k8s.io/klog/v2 v2.80.1 // indirect
	k8s.io/kube-aggregator v0.25.5 // indirect
	k8s.io/kube-openapi v0.0.0-20220803162953-67bda5d908f1 // indirect
	sigs.k8s.io/cli-utils v0.27.0 // indirect
	sigs.k8s.io/json v0.0.0-20220713155537-f223a00ba0e2 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.3 // indirect
)
