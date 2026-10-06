## Validation Checks

The operation resources share one set of rules, since every operation kind has the same `spec` and `status` fields for them. Each resource is served by its own webhook:

- `operation.cattle.io/v1alpha1/etcdsnapshotsaves`
- `operation.cattle.io/v1alpha1/etcdsnapshotrestores`
- `operation.cattle.io/v1alpha1/encryptionkeyrotations`
- `operation.cattle.io/v1alpha1/certificaterotations`

Scope: Namespaced. Operations: CREATE, UPDATE. Deletes are not validated.

The CRDs' own CEL rules require `spec.clusterRef` to name an `apiVersion`, `kind` and `name`, keep it from changing once set, latch `spec.cancel`, and keep `spec.cancel` from being set on a terminal operation. The webhook covers what CEL can't, because it needs a request type or other objects to decide.

### Canceling on create

On create, `spec.cancel` can't be set. CEL can't tell a create from an update, so this is checked here. The request is rejected (400 Bad Request).

### Access to the cluster

On create, and on an update that changes the `spec` (for example, setting `spec.cancel`), the requesting user must have `update` on the cluster `spec.clusterRef` names. Operations change the cluster, so being able to read it isn't enough. The webhook resolves `spec.clusterRef`'s `apiVersion` and `kind` to a resource and performs a SubjectAccessReview: verb `update`, that resource, and the cluster's name, along with its namespace if the resource is namespaced.

- If `spec.clusterRef` doesn't resolve to a resource the cluster serves, the request is rejected (400 Bad Request), since the permission can't be established.
- If it resolves to a namespaced resource but doesn't name a namespace, the request is rejected (400 Bad Request).
- If the review is denied, the request is rejected (403 Forbidden).

Updates that leave the `spec` alone (finalizers, labels) aren't checked, so an operation whose cluster can no longer be resolved can still finish deleting.

### One operation at a time

On create, the request is rejected (400 Bad Request) if another operation on the same cluster, of any kind, is still in progress. An operation is in progress until it has terminated (`status.terminatedAt` is set), which happens after it reaches a terminal phase and its controller has finished with it. Users wait for an operation to finish, or cancel it (`spec.cancel: true`), before creating the next one.

Two references name the same cluster when their API group, kind and name match and, where both name one, their namespace does too. An operation on a cluster-scoped cluster can be in any namespace.

The operations are read from a cache, so two creates in quick succession can both be admitted. The operation controllers then reject whichever one finds the cluster's beacon already held by the other. If the cache hasn't synced yet, which can happen just after the webhook starts, the request fails with a server error for the client to retry, rather than being admitted against an empty cache.

### The cluster's operation whitelist

On create, the webhook reads the object `spec.clusterRef` names, and checks its `operation.cattle.io/whitelisted` annotation. An operation stopped after pausing the cluster (its point of no return) leaves the cluster whitelisted for `etcdsnapshotrestores.operation.cattle.io`, since only an etcd snapshot restore can repair it from there.

- The annotation's value is a comma-separated list of operation resources, each named `<plural>.<group>`. If it is present with at least one entry, the request is rejected (400 Bad Request) unless the resource being created is one of them:

  ```text
  cluster fleet-default/c only permits etcdsnapshotrestores.operation.cattle.io: an earlier operation was stopped after pausing it, and the cluster requires an etcd snapshot restore
  ```

- Without the annotation, or with an empty one, any operation may be created.
- If the object doesn't exist, the request is rejected (400 Bad Request), since an operation on it could never run. If it can't be read for any other reason, the request fails with a server error for the client to retry.

An operation in progress on the cluster is reported first, since it may be the operation that added the whitelist. Updates aren't checked, so an operation running on a whitelisted cluster can always be canceled. The operation controllers check the whitelist again before they change anything, so an operation admitted on a stale read is still turned away.

A succeeded restore removes the annotation. An administrator who has repaired the cluster by other means can remove it by hand; doing so doesn't unpause the cluster.
