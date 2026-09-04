## Validation Checks

The checks apply only to user-initiated requests.
Rancher-initiated requests bypass the validation.

### On delete

A rancher-managed resource quota cannot be deleted by users.
It can be deleted by the `namespace-controller` service account.

### On create and update

A rancher-managed resource quota cannot be created or modified by users.
It can be modified by the `resourcequota-controller` service account.

A resource quota that is not rancher-managed can't be promoted to rancher-managed.
