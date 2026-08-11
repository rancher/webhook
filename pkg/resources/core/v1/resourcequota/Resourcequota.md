## Validation Checks

The checks apply only to user-initiated requests.
Rancher-initiated requests bypass the validation.

### On delete

A rancher-managed resource quota cannot be deleted by users.

### On create and update

A rancher-managed resource quota cannot be created or modified by users.

Neither is it possible to promote an unmanaged resource to rancher-managed.
