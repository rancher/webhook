## Validation Checks

This webhook validates AWSCluster resources (`infrastructure.cluster.x-k8s.io/v1beta2`).

### Scope and Operations

- Resource: `infrastructure.cluster.x-k8s.io/v1beta2/awsclusters`
- Scope: Namespaced
- Operations: CREATE, UPDATE

### Credential Access Check

When an `AWSCluster` references an `AWSClusterStaticIdentity` via `spec.identityRef`, the webhook verifies that the requesting user has `get` permission on the Rancher Cloud Credential Secret that backs the identity.

Steps:
1. If `spec.identityRef` is absent, the request is allowed.
2. If `spec.identityRef.kind` is not `AWSClusterStaticIdentity`, the request is allowed (other identity types are out of scope).
3. On UPDATE: if `spec.identityRef.{kind,name}` is unchanged, the request is allowed (no credential change).
4. The referenced `AWSClusterStaticIdentity` is fetched from the cluster.
   - If not found: request is rejected (400 Bad Request).
   - If lookup fails for any other reason: request is rejected (400 Bad Request).
5. If `AWSClusterStaticIdentity.spec.secretRef` is empty, the request is allowed.
6. A SubjectAccessReview is performed: verb `get`, resource `secrets`, namespace `cattle-global-data`, name = `spec.secretRef`.
   - If denied: request is rejected (403 Forbidden).

The secret is always checked in `cattle-global-data` because Rancher Turtles mirrors the user's Rancher Cloud Credential (stored in `cattle-global-data`) into `capa-system` for the CAPA controller. The access check uses the original Rancher credential namespace.
