# Rancher Webhook

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
The Rancher Webhook is one such controller that runs both in the local cluster and all downstream clusters automatically.

A typical admission controller, such as Rancher's webhook, works as a web-server that receives requests forwarded
by the main API server. If the Webhook runs its custom validation logic for the resource in question
and rejects it because the object's structure violates some custom rules, then the whole request to the API server
is also rejected.

The Go web-server itself is configured by [dynamiclistener](https://github.com/rancher/dynamiclistener).
It handles TLS certificates and the management of associated Secrets for secure communication of other Rancher components with the Webhook.

## Docs

Documentation on each of the resources that are validated or mutated can be found in `docs.md`. It is recommended to review the [kubernetes docs on CRDs](https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/#customresourcedefinitions) as well.

Docs are added by creating a resource-specific readme in the directory of your mutator/validator (e.x. `pkg/resources/$GROUP/$GROUP_VERSION/$RESOURCE/$READABLE_RESOURCE.MD`).
These files should be named with a human-readable version of the resource's name. For example, `GlobalRole.md`.
Running `go generate` will then aggregate these into the user-facing docs in the `docs.md` file.

## Webhooks

Rancher-Webhook is composed of multiple [WebhookHandlers](pkg/admission/admission.go) which is used when creating [ValidatingWebhooks](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#validatingwebhook-v1-admissionregistration-k8s-io) and [MutatingWebhooks](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#mutatingwebhook-v1-admissionregistration-k8s-io).

``` golang
// WebhookHandler base interface for both ValidatingAdmissionHandler and MutatingAdmissionHandler.
// WebhookHandler is used for creating new http.HandlerFunc for each Webhook.
type WebhookHandler interface {

    // GVR returns GroupVersionResource that the Webhook reviews.
    // The returned GVR is used to define the route for accessing this webhook as well as creating the Webhooks Name.
    // Thus the GVR returned must be unique from other WebhookHandlers of the same type e.g.(Mutating or Validating).
    // If a WebhookHandler desires to monitor all resources in a group the Resource defined int he GVR should be "*".
    // If a WebhookHandler desires to monitor a core type the Group can be left empty "".
    GVR() schema.GroupVersionResource

    // Operations returns list of operations that this WebhookHandler supports.
    // Handlers will only be sent request with operations that are contained in the provided list.
    Operations() []v1.OperationType

    // Admit handles the webhook admission request sent to this webhook.
    // The response returned by the WebhookHandler will be forwarded to the kube-api server.
    // If the WebhookHandler can not accurately evaluate the request it should return an error.
    Admit(*Request) (*admissionv1.AdmissionResponse, error)
}

// ValidatingAdmissionHandler is a handler used for creating a ValidationAdmission Webhook.
type ValidatingAdmissionHandler interface {
    WebhookHandler

    // ValidatingWebhook returns a list of configurations to route to this handler.
    //
    // This functions allows ValidatingAdmissionHandler to perform modifications to the default configuration if needed.
    // A default configuration can be made using NewDefaultValidatingWebhook(...)
    // Most Webhooks implementing ValidatingWebhook will only return one configuration.
    ValidatingWebhook(clientConfig v1.WebhookClientConfig) []v1.ValidatingWebhook
}

// MutatingAdmissionHandler is a handler used for creating a MutatingAdmission Webhook.
type MutatingAdmissionHandler interface {
    WebhookHandler

    // MutatingWebhook returns a list of configurations to route to this handler.
    //
    // MutatingWebhook functions allows MutatingAdmissionHandler to perform modifications to the default configuration if needed.
    // A default configuration can be made using NewDefaultMutatingWebhook(...)
    // Most Webhooks implementing MutatingWebhook will only return one configuration.
    MutatingWebhook(clientConfig v1.WebhookClientConfig) []v1.MutatingWebhook
}
```

Any admission controller, as an app, consists of two main things:

1. The configuration which describes the resources and actions for which the webhook is active. This
   configuration also references the Kubernetes service which directs traffic to the actual web-server
   (this Webhook project) that does the work. The configuration exists as [ValidatingWebhookConfiguration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#validatingwebhookconfiguration-v1-admissionregistration-k8s-io)
   and [MutatingWebhookConfiguration](https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.24/#mutatingwebhookconfiguration-v1-admissionregistration-k8s-io) resources.
2. The actual web-server with all the validation and mutation logic found in each object's Admit method.

_Note: both the ValidatingWebhookConfiguration and MutatingWebhookConfiguration are dynamically created at
webhook startup, not beforehand._

All objects with custom validation logic exist in the `pkg/resources` package.

### Validation

Both Mutating and Validating webhooks can be used for basic validation of user input.
[A ValidatingAdmissionHandler should be used when validation is needed after all mutations are completed.](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#what-are-admission-webhooks)

For example, there is a
`globalrole` package that has a type with an Admit method. Every time the local cluster's kube-api server receives a
request to create or update a GlobalRole (a Rancher CRD), the Webhook, being an instance of an
admission controller, intercepts the request. The Admit method for Global Roles runs.
It inspects the Global Role object and leads it through a series of custom checks. One of them
ensures that each rule of the GlobalRole has at least one verb. If it does not, then the Webhook
changes returns a response value with `Allowed` set to false.

```go
    for _, rule := range newGR.Rules {
        if len(rule.Verbs) == 0 {
            return &admissionv1.AdmissionResponse{
                Result: &metav1.Status{
                    Status:  "Failure",
                    Message: "GlobalRole.Rules: PolicyRules must have at least one verb",
                    Reason:  metav1.StatusReasonBadRequest,
                    Code:    http.StatusBadRequest,
                },
                Allowed: false,
            }, nil
        }
    }
```

This logic is the main part of object inspection and admission control.

### Mutation

A MutatingAdmissionHandler should be used when the data being updated needs to be modified. All modifications must be recorded using a [JSONpatch](https://jsonpatch.com/). This can be done easily using the `pkg/patch` library for example the [MutatingAdmissionHandler for secrets](pkg/resources/core/v1/secret/mutator.go) add the creator's username as an annotation then creates a patch that is attached to the response.

```go
    newSecret.Annotations[auth.CreatorIDAnn] = request.UserInfo.Username
    response := &admissionv1.AdmissionResponse{}
    if err := patch.CreatePatch(request.Object.Raw, newSecret, response); err != nil {
        return nil, fmt.Errorf("failed to create patch: %w", err)
    }
    response.Allowed = true
    return response, nil
```

### Creating a WebhookHandler

The `pkg/server` package is the main setup package of the Webhook server itself. The package defines the rules for resources and actions for which the Webhook will
be active. These are later brought to life as cluster-wide Kubernetes resources
(ValidatingWebhookConfiguration and MutatingWebhookConfiguration).
It also binds resources with their respective admission handlers.

To add a new Webhook handler one simply needs to create a struct that satisfies either the ValidatingAdmissionHandler or MutatingAdmissionhandler Interface. Then add an initialized instance of the struct in [`pkg/server/handler.go`](pkg/server/handlers.go)

## Building

```bash
make
```

## Running

```bash
./bin/webhook
```

## Development

1. Get a new address that forwards to `https://localhost:9443` using ngrok.

    ```bash
    ngrok http https://localhost:9443
    ```

2. Run the webhook with the given address and the kubeconfig for the cluster hosting Rancher.

    ``` bash
    export KUBECONFIG=<rancher_kube_config>
    export CATTLE_WEBHOOK_URL="https://<NGROK_URL>.ngrok.io"
    ./bin/webhook
    ```

After 15 seconds the webhook will update the `ValidatingWebhookConfiguration` and `MutatingWebhookConfiguration` in the Kubernetes cluster to point at the locally running instance.

> :warning: Kubernetes API server authentication will not work with ngrok.

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
