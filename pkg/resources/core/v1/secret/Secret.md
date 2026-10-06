## Validation Checks

### On delete

A secret cannot be deleted if its deletion request has an orphan policy,
and the secret has roles or role bindings dependent on it.

### On create and update

For Secrets of type `rke.cattle.io/machine-plan`, if `data.plan` is present, its value is parsed using the shared plan schema from `pkg/plan`.
If the value is not valid JSON or does not conform to the plan schema, the request is rejected.

### On update

For Secrets of type `rke.cattle.io/machine-plan`, the labels tying the secret to its cluster and its machine can't be changed or removed once set:

- `plan.cattle.io/cluster-group`, `plan.cattle.io/cluster-kind`, `plan.cattle.io/cluster-name`
- `plan.cattle.io/machine-group`, `plan.cattle.io/machine-kind`, `plan.cattle.io/machine-name`
- `rke.cattle.io/cluster-name`

Each label is compared with the same key on the old and new secret. A label the old secret doesn't have may be added, which is how the controllers that register a machine stamp them. Changing one, including to an empty value, or removing one, is rejected (400 Bad Request). The cluster's beacon is found through `plan.cattle.io/cluster-name`, so changing the cluster labels would let a writer point a plan at a beacon it holds; changing the machine labels would detach a plan from its machine.

### Machine-plan writers

For Secrets of type `rke.cattle.io/machine-plan`, on create and update, a write that assigns, retries, cancels or pauses the plan must come from whoever holds the cluster's beacon. That keeps an operation that has been canceled, or has lost the beacon, from writing a plan once the next operation holds it.

A write is checked only if it changes, from the old secret (or from nothing, on create), any of:

- data: `plan`, `max-failures`, `failure-threshold`, or `plan-state` when it becomes `pending`;
- annotations: `plan.cattle.io/canceled`, `plan.cattle.io/paused`, `plan.cattle.io/writer`, `plan.cattle.io/attempt`.

Everything else, which is the agent's feedback (plan-state progress, revisions, checkpoints, probe statuses, outputs) and other controllers' bookkeeping, is allowed without a lookup, since it keeps being written after the writer has released the beacon.

For a checked write:

1. The beacon is `(namespace, labels["plan.cattle.io/cluster-name"])` of the secret, the old one on update. If the label isn't set, the write is allowed.
2. The beacon is read from the webhook's cache. If it doesn't exist, the write is allowed. If it can't be read, the request fails with a server error for the writer to retry.
3. If the new secret has no `plan.cattle.io/writer` annotation, the write is allowed. This is for one release, so the webhook can run alongside a Rancher that doesn't name its writers yet.
4. The write is allowed if the writer is the beacon's owner, or the delegate the owner last handed the beacon to. Otherwise, including when nobody holds the beacon, it is rejected (403 Forbidden):

   ```text
   machine-plan fleet-default/m-plan written by <writer>, but the beacon fleet-default/c is held by <owner>
   ```

The cache can trail the beacon by a moment after it changes hands, so the new holder's first writes can be rejected; writers retry.

## Mutation Checks

### On create

For all secrets of type `provisioning.cattle.io/cloud-credential`, 
places a `field.cattle.io/creatorId` annotation with the name of the user as the value.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` does not get set.

For secrets stored in the `cattle-local-user-passwords` namespace containing local users passwords:
- Verifies the password has the minimum required length.
- Verifies the password is not the same as the username.
- Encrypts the password using pbkdf2.

### On delete

Checks if there are any RoleBindings owned by this secret which provide access to a role granting access to this secret.
If yes, the webhook redacts the role, so that it only grants a deletion permission.
