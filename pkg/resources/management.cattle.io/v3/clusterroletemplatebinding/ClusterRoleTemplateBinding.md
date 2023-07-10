## Validation Checks

### Escalation Prevention

Users can only create/update ClusterRoleTemplateBindings which grant permissions to RoleTemplates with rights less than or equal to those they currently possess. This is to prevent privilege escalation. 

### Invalid Fields - Create

Users cannot create ClusterRoleTemplateBindings which violate the following constraints:
- Either a user subject (through "UserName" or "UserPrincipalName") or a group subject (through "GroupName" or "GroupPrincipalName") must be specified; both a user subject and group subject cannot be specified
- A "ClusterName" must be specified
- The roleTemplate indicated in "RoleTemplateName" must be:
  - Valid (i.e. is an existing `roleTemplate` object in the `management.cattle.io/v3` apiGroup)
  - Not locked (i.e. `roleTemplate.Locked` must be `false`)

### Invalid Fields - Update

Users cannot update the following fields after creation:
- RoleTemplateName
- ClusterName

Users can update the following fields if they have not been set, but after they have been set they cannot be changed:
- UserName
- UserPrincipalName
- GroupName
- GroupPrincipalName

In addition, as in the create validation, both a user subject and a group subject cannot be specified.
