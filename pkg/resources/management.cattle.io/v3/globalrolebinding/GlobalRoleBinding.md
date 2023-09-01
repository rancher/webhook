## Validation Checks

Note: all checks are bypassed if the GlobalRoleBinding is being deleted, or if only the metadata fields are being updated.

### Escalation Prevention

Users can only create/update GlobalRoleBindings with rights less than or equal to those they currently possess. This is to prevent privilege escalation. 

### Valid Global Role Reference

GlobalRoleBindings must refer to a valid global role (i.e. an existing `GlobalRole` object in the `management.cattle.io/v3` apiGroup). In addition, on creation, all RoleTemplates which are referred to in the `inheritedClusterRoles` field must exist and not be locked. 
