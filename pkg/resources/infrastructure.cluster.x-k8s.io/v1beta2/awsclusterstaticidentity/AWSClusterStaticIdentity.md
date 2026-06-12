## Validation Checks

This webhook validates AWSClusterStaticIdentity resources (`infrastructure.cluster.x-k8s.io/v1beta2`).

### Scope and Operations

- Resource: `infrastructure.cluster.x-k8s.io/v1beta2/awsclusterstaticidentities`
- Scope: Cluster
- Operations: CREATE, UPDATE

### Credential Access Check

When an `AWSClusterStaticIdentity` references a Secret via `spec.secretRef`, the webhook checks whether that secret is a Rancher-managed Cloud Credential. If it is, the requesting user must have `get` permission on it.

Steps:
1. If `spec.secretRef` is empty, the request is allowed.
2. The webhook checks whether a Secret named `spec.secretRef` exists in `cattle-global-data`.
   - If **no** such secret exists: the identity is considered user-managed and the request is allowed.
   - If the cache lookup fails with an unexpected error: the request is rejected to fail closed.
3. If the secret exists in `cattle-global-data`, it is a Rancher Cloud Credential mirrored by Turtles. A SubjectAccessReview is performed on every CREATE and UPDATE (regardless of whether `spec.secretRef` changed): verb `get`, resource `secrets`, namespace `cattle-global-data`, name = `spec.secretRef`.
   - If denied: request is rejected (403 Forbidden).

### Rancher Cloud Credentials

Rancher Turtles mirrors user Cloud Credentials (stored in `cattle-global-data`) into the CAPA provider namespace (`capa-system`) for the CAPA controller to consume. The presence of a matching secret in `cattle-global-data` is the signal that a credential is Rancher-managed and subject to access enforcement. User-managed secrets that exist only in `capa-system` are not affected.
