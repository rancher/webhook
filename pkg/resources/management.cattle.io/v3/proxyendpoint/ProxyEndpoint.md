## Validation Checks

### Overly Broad Wildcard Check

Users may only create route entries within a ProxyEndpoint CR which

+ Are Absolute domains (`www.myapi.com`)
+ Are partial, inline, wildcards (`www.%.myapi.com`)
+ Are prefix wildcards (`*.myapi.com`, `*myapi.com`)
+ Do not include protocols (`https://`, etc.)

Some of these checks are also done before a request is sent to the webhook, using kubebuilder Pattern comments on the CRD itself. Others, such as the overly broad wildcard check (e.g. `%.com`, `subdomain.%.com`), are done in the webhook as a regular expression would not be sufficient. In the event that the webhook is not running, the Rancher proxy also verifies that the route is not overly broad and silently ignores it if it is.  