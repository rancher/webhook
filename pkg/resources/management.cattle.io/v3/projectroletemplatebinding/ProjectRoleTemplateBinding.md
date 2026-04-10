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

### Duplicate ProjectRoleTemplateBinding Prevention

On creation, the webhook prevents the creation of a `ProjectRoleTemplateBinding` if another one already exists with the same subject and role in the same project.
This ensures that a user or group is not granted the same project-level role multiple times.

A binding is considered a duplicate if another non-deleting `ProjectRoleTemplateBinding` exists in the same namespace with the exact same values for:
- `roleTemplateName`
- The subject, which is determined by one of the following fields:
  - `userName`
  - `userPrincipalName`
  - `groupName`
  - `groupPrincipalName`

If a conflicting binding exists but is already marked for deletion (has a non-nil `DeletionTimestamp`), it is ignored, allowing the creation to proceed.

## Mutation Checks

### On create

When a `ProjectRoleTemplateBinding` is created using the `generateName` pattern (i.e. `metadata.name` is empty), the webhook replaces the server-generated random name with a deterministic `metadata.name` based on a hash of the binding's content.

When the client sets an explicit `metadata.name`, the mutator does nothing. This preserves backward compatibility for public API consumers and customer automations that depend on specific resource names. The validating webhook's [duplicate check](#duplicate-projectroletemplatebinding-prevention) provides additional protection against duplicate bindings created with different explicit names.

The deterministic name is computed as:

```
prefix + lowercase(base32(sha256(subject + "/" + roleTemplateName + "/" + projectName))[:10])
```

The prefix is taken from `metadata.generateName` if set, otherwise defaults to `prtb-`.

The subject is resolved using the following priority order:
1. `UserPrincipalName`
2. `UserName`
3. `GroupPrincipalName`
4. `GroupName`
5. `ServiceAccount`

If no subject is set, the mutator passes the request through without modification (the validating webhook will reject it).

This ensures that two identical concurrent requests using `generateName` produce the same resource name. The Kubernetes API server will reject the second request with a `409 Conflict`, preventing duplicate bindings even when requests race past the validating webhook.

