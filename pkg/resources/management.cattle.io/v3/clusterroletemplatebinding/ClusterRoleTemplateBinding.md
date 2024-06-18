## Validation Checks

### Escalation Prevention

Users can only create/update ClusterRoleTemplateBindings which grant permissions to RoleTemplates with rights less than or equal to those they currently possess. This is to prevent privilege escalation.
For external RoleTemplates (RoleTemplates with `external` set to `true`), if the `external-rules` feature flag is enabled and `ExternalRules` is specified in the roleTemplate in `RoleTemplateName`,
`ExternalRules` will be used for authorization. Otherwise (if the feature flag is off or `ExternalRules` are nil), the rules from the backing `ClusterRole` in the local cluster will be used.

### Invalid Fields - Create

Users cannot create ClusterRoleTemplateBindings which violate the following constraints:
- Either a user subject (through `UserName` or `UserPrincipalName`) or a group subject (through `GroupName` or `GroupPrincipalName`) must be specified; both a user subject and a group subject cannot be specified
- `ClusterName` must be specified
- The roleTemplate indicated in `RoleTemplateName` must be:
  - Provided as a non-empty value
  - Valid (i.e. is an existing `roleTemplate` object of given name in the `management.cattle.io/v3` API group)
  - Not locked (i.e. `roleTemplate.Locked` must be `false`)
  - Associated with its appropriate context (`roleTemplate.Context` must be equal to "cluster")

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
