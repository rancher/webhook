## Validation Checks

The checks apply only to user-initiated requests.
Rancher-initiated requests bypass the validation.

### On delete

A rancher-managed limit range cannot be deleted by users.
It can only be deleted by the builtin service account `namespace-controller`.

### On create and update

A rancher-managed limit range cannot be created or modified by 

A limit range that is not rancher-managed can't be promoted to rancher-managed.
