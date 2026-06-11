## Validation Checks

This webhook validates AWSClusterStaticIdentity resources (`infrastructure.cluster.x-k8s.io/v1beta2`).

### Scope and Operations

- Resource: `infrastructure.cluster.x-k8s.io/v1beta2/awsclusterstaticidentities`
- Scope: Cluster
- Operations: CREATE, UPDATE

### Credential Access Check

When an `AWSClusterStaticIdentity` is Rancher-managed and references a Secret via `spec.secretRef`, the webhook verifies that the requesting user has `get` permission on the corresponding Rancher Cloud Credential.

Steps:
1. If the identity does **not** carry the annotation `cluster-api.cattle.io/source-id`, the request is allowed. Only Rancher Turtles-managed identities are subject to the credential check.
2. If `spec.secretRef` is empty, the request is allowed.
3. On UPDATE: if `spec.secretRef` is unchanged, the request is allowed (no credential change).
4. A SubjectAccessReview is performed: verb `get`, resource `secrets`, namespace `cattle-global-data`, name = `spec.secretRef`.
   - If denied: request is rejected (403 Forbidden).

### Rancher-managed Identities

The annotation `cluster-api.cattle.io/source-id` is set by Rancher Turtles on identities it manages. Its presence signals that the identity's backing Secret is a Rancher Cloud Credential mirrored into the CAPA provider namespace. Only these identities require a credential access check.

The secret is always checked in `cattle-global-data` because Rancher Turtles mirrors the user's Rancher Cloud Credential (stored in `cattle-global-data`) into `capa-system` for the CAPA controller. The access check uses the original Rancher credential namespace.
