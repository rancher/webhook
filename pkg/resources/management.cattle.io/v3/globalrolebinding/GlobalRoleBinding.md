## Validation Checks

Note: all checks are bypassed if the GlobalRoleBinding is being deleted, or if only the metadata fields are being updated.

### Escalation Prevention

Users can only create/update GlobalRoleBindings with rights less than or equal to those they currently possess. This is to prevent privilege escalation. 

### Valid Global Role Reference

GlobalRoleBindings must refer to a valid global role (i.e. an existing `GlobalRole` object in the `management.cattle.io/v3` apiGroup).

This escalation check is bypassed if a user has the `bind` verb on the GlobalRole that they are trying to bind to (through creating or updating a GlobalRoleBinding to that GlobalRole). This can also be given through a wildcard permission (i.e. the `*` verb also gives `bind`).

### Invalid Fields - Update
Users cannot update the following fields after creation:
- `userName`
- `groupPrincipalName`
- `globalRoleName`


### Invalid Fields - Create
GlobalRoleBindings must have either `userName` or `groupPrincipalName`, but not both.
All RoleTemplates which are referred to in the `inheritedClusterRoles` field must exist and not be locked. 

## Mutation Checks

### On create

When a GlobalRoleBinding is created an owner reference is created on the binding referring to the backing GlobalRole defined by `globalRoleName`.
