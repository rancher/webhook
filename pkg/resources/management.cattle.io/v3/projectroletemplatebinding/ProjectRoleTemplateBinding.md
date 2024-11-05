## Validation Checks

### Escalation Prevention

Users can only create/update ProjectRoleTemplateBindings with rights less than or equal to those they currently possess.
This is to prevent privilege escalation.
For external RoleTemplates (RoleTemplates with `external` set to `true`), if the `external-rules` feature flag is enabled and `ExternalRules` is specified in the roleTemplate in `RoleTemplateName`,
`ExternalRules` will be used for authorization. Otherwise, if `ExternalRules` are nil when the feature flag is on, the rules from the backing `ClusterRole` in the local cluster will be used.

### Invalid Fields - Create

Users cannot create ProjectRoleTemplateBindings that violate the following constraints:

- The `ProjectName` field must be:
    - Provided as a non-empty value
    - Specified using the format of `clusterName:projectName`; `clusterName` is the `metadata.name` of a cluster, and `projectName` is the `metadata.name` of a project
    - The `projectName` part of the field must match the namespace of the ProjectRoleTemplateBinding
    - Refer to a valid project and cluster (both must exist and project.Spec.ClusterName must equal the cluster)
- Either a user subject (through `UserName` or `UserPrincipalName`), or a group subject (through `GroupName`
  or `GroupPrincipalName`), or a service account subject (through `ServiceAccount`) must be specified. Exactly one
  subject type of the three must be provided.
- The roleTemplate indicated in `RoleTemplateName` must be:
    - Provided as a non-empty value
    - Valid (there must exist a `roleTemplate` object of given name in the `management.cattle.io/v3` API group)
    - Not locked (`roleTemplate.Locked` must be `false`)
    - Associated with its appropriate context (`roleTemplate.Context` must be equal to "project")

### Invalid Fields - Update

Users cannot update the following fields after creation:

- RoleTemplateName
- ProjectName
- ServiceAccount

Users can update the following fields if they had not been set. But after getting initial values, the fields cannot be
changed:

- UserName
- UserPrincipalName
- GroupName
- GroupPrincipalName

In addition, as in the create validation, both a user subject and a group subject cannot be specified.
