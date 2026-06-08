## Validation Checks

This webhook validates AWSClusterStaticIdentity resources (`infrastructure.cluster.x-k8s.io/v1beta2`).

### Scope and Operations

- Resource: `infrastructure.cluster.x-k8s.io/v1beta2/awsclusterstaticidentities`
- Scope: Cluster
- Operations: CREATE, UPDATE

### Credential Access Check

When an `AWSClusterStaticIdentity` references a Secret via `spec.secretRef`, the webhook verifies that the requesting user has `get` permission on the corresponding Rancher Cloud Credential.

Steps:
1. If `spec.secretRef` is empty, the request is allowed.
2. On UPDATE: if `spec.secretRef` is unchanged, the request is allowed (no credential change).
3. A SubjectAccessReview is performed: verb `get`, resource `secrets`, namespace `cattle-global-data`, name = `spec.secretRef`.
   - If denied: request is rejected (403 Forbidden).

The secret is always checked in `cattle-global-data` because Rancher Turtles mirrors the user's Rancher Cloud Credential (stored in `cattle-global-data`) into `capa-system` for the CAPA controller. The access check uses the original Rancher credential namespace.
