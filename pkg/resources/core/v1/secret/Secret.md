## Validation Checks

A secret cannot be deleted if its deletion request has an orphan policy,
and the secret has roles or role bindings dependent on it.

## Mutation Checks

### On create

For all secrets of type `provisioning.cattle.io/cloud-credential`, 
places a `field.cattle.io/creatorId` annotation with the name of the user as the value.

### On delete

Checks if there are any RoleBindings owned by this secret which provide access to a role granting access to this secret.
If yes, the webhook redacts the role, so that it only grants a deletion permission.
