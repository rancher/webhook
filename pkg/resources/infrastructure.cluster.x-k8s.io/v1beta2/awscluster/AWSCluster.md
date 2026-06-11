## Validation Checks

This webhook validates AWSCluster resources (`infrastructure.cluster.x-k8s.io/v1beta2`).

### Scope and Operations

- Resource: `infrastructure.cluster.x-k8s.io/v1beta2/awsclusters`
- Scope: Namespaced
- Operations: CREATE, UPDATE

### Credential Access Check

When an `AWSCluster` references an `AWSClusterStaticIdentity` via `spec.identityRef`, the webhook fetches the current state of that identity and checks whether its credential is a Rancher-managed Cloud Credential. If it is, the requesting user must have `get` permission on that credential.

Steps:
1. If `spec.identityRef` is absent, the request is allowed.
2. If `spec.identityRef.kind` is not `AWSClusterStaticIdentity`, the request is allowed (other identity types are out of scope).
3. The referenced `AWSClusterStaticIdentity` is fetched from the cluster. This fetch always occurs on both CREATE and UPDATE, because the identity itself may have changed between requests (different `spec.secretRef`, credential removed).
   - If not found: request is rejected (400 Bad Request).
   - If the lookup fails for any other reason: request is rejected (400 Bad Request).
4. If `AWSClusterStaticIdentity.spec.secretRef` is empty, the request is allowed.
5. The webhook checks whether a Secret named `spec.secretRef` exists in `cattle-global-data`.
   - If **no** such secret exists: the identity is considered user-managed and the request is allowed.
   - If the cache lookup fails with an unexpected error: the request is rejected to fail closed.
6. If the secret exists in `cattle-global-data`, it is a Rancher Cloud Credential mirrored by Turtles. A SubjectAccessReview is performed: verb `get`, resource `secrets`, namespace `cattle-global-data`, name = `spec.secretRef`.
   - If denied: request is rejected (403 Forbidden).

### Rancher Cloud Credentials

Rancher Turtles mirrors user Cloud Credentials (stored in `cattle-global-data`) into the CAPA provider namespace (`capa-system`) for the CAPA controller to consume. The presence of a matching secret in `cattle-global-data` is the signal that a credential is Rancher-managed and subject to access enforcement. User-managed secrets that exist only in `capa-system` are not affected.
