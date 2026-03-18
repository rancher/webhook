module github.com/rancher/webhook

go 1.25.0

toolchain go1.25.7

replace (
	k8s.io/apiextensions-apiserver => k8s.io/apiextensions-apiserver v0.35.0
	k8s.io/cli-runtime => k8s.io/cli-runtime v0.35.0
	k8s.io/client-go => k8s.io/client-go v0.35.0
	k8s.io/cloud-provider => k8s.io/cloud-provider v0.35.0
	k8s.io/cluster-bootstrap => k8s.io/cluster-bootstrap v0.35.0
	k8s.io/code-generator => k8s.io/code-generator v0.35.0
	k8s.io/component-helpers => k8s.io/component-helpers v0.35.0
	k8s.io/controller-manager => k8s.io/controller-manager v0.35.0
	k8s.io/cri-api => k8s.io/cri-api v0.35.0
	k8s.io/cri-client => k8s.io/cri-client v0.35.0
	k8s.io/csi-translation-lib => k8s.io/csi-translation-lib v0.35.0
	k8s.io/dynamic-resource-allocation => k8s.io/dynamic-resource-allocation v0.35.0
	k8s.io/endpointslice => k8s.io/endpointslice v0.35.0
	k8s.io/externaljwt => k8s.io/externaljwt v0.35.0
	k8s.io/kube-aggregator => k8s.io/kube-aggregator v0.35.0
	k8s.io/kube-controller-manager => k8s.io/kube-controller-manager v0.35.0
	k8s.io/kube-proxy => k8s.io/kube-proxy v0.35.0
	k8s.io/kube-scheduler => k8s.io/kube-scheduler v0.35.0
	k8s.io/kubectl => k8s.io/kubectl v0.35.0
	k8s.io/kubelet => k8s.io/kubelet v0.35.0
	k8s.io/legacy-cloud-providers => k8s.io/legacy-cloud-providers v0.35.0
	k8s.io/metrics => k8s.io/metrics v0.35.0
	k8s.io/mount-utils => k8s.io/mount-utils v0.35.0
	k8s.io/sample-apiserver => k8s.io/sample-apiserver v0.35.0
)

require (
	github.com/blang/semver v3.5.1+incompatible
	github.com/evanphx/json-patch v5.9.11+incompatible
	github.com/go-ldap/ldap/v3 v3.4.11
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.1
	github.com/rancher/dynamiclistener v0.8.0
	github.com/rancher/jsonpath v0.0.0-20250620213443-ad24535cf0c1
	github.com/rancher/lasso v0.2.7
	github.com/rancher/rancher/pkg/apis v0.0.0-20260211194119-d0c9ffaf3cb0
	github.com/rancher/rke v1.8.6
	github.com/rancher/wrangler/v3 v3.5.0-rc.2
	github.com/robfig/cron v1.2.0
	github.com/sirupsen/logrus v1.9.4
	github.com/stretchr/testify v1.11.1
	go.uber.org/mock v0.6.0
	golang.org/x/text v0.35.0
	golang.org/x/tools v0.43.0
	k8s.io/api v0.35.0
	k8s.io/apimachinery v0.35.0
	k8s.io/apiserver v0.35.0
	k8s.io/client-go v12.0.0+incompatible
	k8s.io/kubernetes v1.35.0
	k8s.io/pod-security-admission v0.35.0
	k8s.io/utils v0.0.0-20260108192941-914a6e750570
	sigs.k8s.io/controller-runtime v0.23.0
	sigs.k8s.io/yaml v1.6.0
)

require (
	cel.dev/expr v0.24.0 // indirect
	github.com/NYTimes/gziphandler v1.1.1 // indirect
	github.com/adrg/xdg v0.5.3 // indirect
	github.com/antlr4-go/antlr/v4 v4.13.0 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.5.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-openapi/swag/cmdutils v0.25.4 // indirect
	github.com/go-openapi/swag/conv v0.25.4 // indirect
	github.com/go-openapi/swag/fileutils v0.25.4 // indirect
	github.com/go-openapi/swag/jsonname v0.25.4 // indirect
	github.com/go-openapi/swag/jsonutils v0.25.4 // indirect
	github.com/go-openapi/swag/loading v0.25.4 // indirect
	github.com/go-openapi/swag/mangling v0.25.4 // indirect
	github.com/go-openapi/swag/netutils v0.25.4 // indirect
	github.com/go-openapi/swag/stringutils v0.25.4 // indirect
	github.com/go-openapi/swag/typeutils v0.25.4 // indirect
	github.com/go-openapi/swag/yamlutils v0.25.4 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/cel-go v0.26.0 // indirect
	github.com/gorilla/websocket v1.5.4-0.20250319132907-e064f32e3674 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.26.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/pborman/uuid v1.2.1 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/rancher/apiserver v0.9.0 // indirect
	github.com/rancher/kubernetes-provider-detector v0.1.6-0.20240606163014-fcae75779379 // indirect
	github.com/rancher/remotedialer v0.6.0-rc.1 // indirect
	github.com/rancher/steve v0.9.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/spf13/cobra v1.10.0 // indirect
	github.com/stoewer/go-strcase v1.3.0 // indirect
	github.com/tinylib/msgp v1.6.3 // indirect
	github.com/urfave/cli/v2 v2.27.7 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	go.etcd.io/etcd/api/v3 v3.6.5 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.6.5 // indirect
	go.etcd.io/etcd/client/v3 v3.6.5 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.60.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.34.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.34.0 // indirect
	go.opentelemetry.io/otel/metric v1.37.0 // indirect
	go.opentelemetry.io/otel/sdk v1.37.0 // indirect
	go.opentelemetry.io/proto/otlp v1.5.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250707201910-8d1bb00bc6a7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251002232023-7c0ddcbb5797 // indirect
	google.golang.org/grpc v1.75.1 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.13.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	k8s.io/kms v0.35.0 // indirect
	modernc.org/libc v1.66.10 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.40.1 // indirect
	sigs.k8s.io/apiserver-network-proxy/konnectivity-client v0.31.2 // indirect
	sigs.k8s.io/cli-utils v0.37.2 // indirect
)

require (
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/emicklei/go-restful/v3 v3.13.0 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.8-0.20250403174932-29230038a667 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-openapi/jsonpointer v0.22.4 // indirect
	github.com/go-openapi/jsonreference v0.21.4 // indirect
	github.com/go-openapi/swag v0.25.4 // indirect
	github.com/google/gnostic-models v0.7.1 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.5 // indirect
	github.com/prometheus/procfs v0.19.2 // indirect
	github.com/rancher/aks-operator v1.13.0-rc.4 // indirect
	github.com/rancher/ali-operator v1.13.0-rc.2 // indirect
	github.com/rancher/eks-operator v1.13.0-rc.4 // indirect
	github.com/rancher/fleet/pkg/apis v0.15.0-alpha.6 // indirect
	github.com/rancher/gke-operator v1.13.0-rc.3 // indirect
	github.com/rancher/norman v0.9.0
	github.com/robfig/cron/v3 v3.0.1 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.opentelemetry.io/otel v1.37.0 // indirect
	go.opentelemetry.io/otel/trace v1.37.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/net v0.52.0
	golang.org/x/oauth2 v0.34.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/term v0.41.0 // indirect
	golang.org/x/time v0.14.0 // indirect
	gomodules.xyz/jsonpatch/v2 v2.5.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/evanphx/json-patch.v5 v5.9.11
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	k8s.io/apiextensions-apiserver v0.35.0 // indirect
	k8s.io/code-generator v0.35.0 // indirect
	k8s.io/component-base v0.35.0 // indirect
	k8s.io/component-helpers v0.35.0 // indirect
	k8s.io/controller-manager v0.35.0 // indirect
	k8s.io/gengo v0.0.0-20250130153323-76c5745d3511 // indirect
	k8s.io/gengo/v2 v2.0.0-20250922181213-ec3ebc5fd46b // indirect
	k8s.io/klog/v2 v2.130.1 // indirect
	k8s.io/kube-aggregator v0.35.0 // indirect
	k8s.io/kube-openapi v0.0.0-20251125145642-4e65d59e963e // indirect
	k8s.io/kubelet v0.35.0 // indirect
	sigs.k8s.io/cluster-api v1.11.5
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.1 // indirect
)
