Rancher Webhook
========
 Rancher webhook is both a validating admission webhook and mutating admission webhook for Kubernetes. 


[Explanation of Webhooks in Kubernetes](
https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)


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
