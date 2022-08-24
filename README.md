Rancher Webhook
========
 Rancher webhook is both a validating admission webhook and a mutating admission webhook for Kubernetes.

[Explanation of Webhooks in Kubernetes](
https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)

## Background
The Rancher Webhook is an instance of a Kubernetes admission controller.
Admission controllers are a standard Kubernetes mechanism to intercept requests to a cluster's
API server and perform validation or mutation of resources prior to their persistence in
the cluster database.
The validation and mutation are performed by custom code whose logic is defined by the instance of an admission controller.
Cluster administrators may create many such controllers that perform custom validation or mutation in series.
The Rancher Webhook is one such controller that runs only in the local cluster.

A typical admission controller, such as Rancher's webhook, works as a web-server that receives requests forwarded
by the main API server. If the Webhook runs its custom validation logic for the resource in question
and rejects it because the object's structure violates some custom rules, then the whole request to the API server
is also rejected.

A significant part of the low-level functionality of the Webhook's web-server is implemented
in [Wrangler](https://github.com/rancher/wrangler). Wrangler provides code for error handling, top-level routing,
object decoding and response encoding.

The Go web-server itself is configured by [dynamiclistener](https://github.com/rancher/dynamiclistener).
It handles TLS certificates and the management of associated Secrets for secure communication of other Rancher components with the Webhook.

## Webhook
The Webhook focuses on the resource matching rules and admission logic for each relevant
object that needs custom validation. Each object that the Webhook inspects has an `Admit` method which takes a webhook request and response. 
Its main job is to extract the object from the request,
perform custom validation or mutation, and modify the response as needed, thus signaling if validation succeeded
or failed. When the Webhook is done, it returns control to Wrangler which then handles the sending of the verdict
of the admission controller.

`Admit(Response, Request) error`

Note that each object's Admit method returns an error.
This error is not to signify that an object violates some validation rules, but rather to signal that
the validation process itself has encountered an error. If an admission controller has deemed a resource
invalid for persistence, it means it itself has succeeded.

The resources that the Webhook validates or mutates are declared in the `pkg/resources/validation`
and `pkg/resources/mutation`, respectively.

Any admission controller, as an app, consists of two main things:
1. The configuration which describes the resources and actions for which the webhook is active. This
   configuration also references the Kubernetes service which directs traffic to the actual web-server
   (this Webhook project) that does the work. The configuration exists as ValidatingWebhookConfiguration
   and MutatingWebhookConfiguration global resources.
2. The actual web-server with all the validation and mutation logic found in each object's Admit method.

Both the ValidatingWebhookConfiguration and MutatingWebhookConfiguration are fully created at
webhook startup, not beforehand. Usually, these key admission controller resources are deployed as manifests along with those
for the web-server deployment and service, but Rancher is different here.

All objects with custom validation logic exist in the `pkg/resources` package. For example, there is a
`globalrole` package that has a type with an Admit method. Every time the local cluster's kube-api server receives a
request to create or update a Global Role (a Rancher resource), the Webhook, being an instance of an
admission controller, intercepts the request. The Admit method for Global Roles runs.
It inspects the Global Role object and leads it through a series of custom checks. One of them
ensures that each rule of the Global Role has at least one verb. If it does not, then the Webhook
changes the response value by setting its `Allowed` field to false, meaning validation has failed. It then returns.

```go
for _, rule := range newGR.Rules {
     if len(rule.Verbs) == 0 {
         response.Result = &metav1.Status{
             Status:  "Failure",
             Message: "GlobalRole.Rules: PolicyRules must have at least one verb",
             Reason:  metav1.StatusReasonBadRequest,
             Code:    http.StatusBadRequest,
         }
         response.Allowed = false
         return nil
     }
 }
```

This logic is the main part of object inspection and admission control, and the rest is wrapped by
Wrangler.

The `pkg/server` package is the main setup package of the Webhook server itself as well as all the low-level
components defined in Wrangler. The package defines the rules for resources and actions for which the Webhook will
be active. These are later brought to life as cluster-wide Kubernetes resources
(ValidatingWebhookConfiguration and MutatingWebhookConfiguration).
It also binds resources with their respective admission handlers - this is done for the Webhook
router, which is also defined in Wrangler.

## Building

```bash
make
```

## Running

```bash
./bin/webhook
```

## Development

To direct traffic to a locally running instance ngrok can be used:

```bash
ngrok http https://localhost:9443
```

Update the `WebhookClientConfig` by adding a `URL` and removing the `Service` and `CABundle` fields. Update the `URL` with the ngrok url `https://<myngrok>.ngrok.io/v1/webhook/validation`

```go
url := "https://<myngrok>.ngrok.io/v1/webhook/validation"
{
	Name: "rancherauth.cattle.io",
	ClientConfig: v1.WebhookClientConfig{
		URL: &url,
	},
....
}
```

The webhook will update the `ValidatingWebhookConfiguration` in Kubernetes to then point at the locally running instance.
## License
Copyright (c) 2019-2021 [Rancher Labs, Inc.](http://rancher.com)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

[http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
