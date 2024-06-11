# core/v1 

## Namespace 

### Validation Checks

Note: The `kube-system` namespace, unlike other namespaces, has a `failPolicy` of `ignore` on update calls.

#### Project annotation
Verifies that the annotation `field.cattle.io/projectId` value can only be updated by users with the `manage-namespaces` 
verb on the project specified in the annotation.

#### PSA Label Validation

Validates that users who create or edit a PSA enforcement label on a namespace have the `updatepsa` verb on `projects` 
in `management.cattle.io/v3`. See the [upstream docs](https://kubernetes.io/docs/concepts/security/pod-security-admission/) 
for more information on the effect of these labels.

The following labels are considered relevant for PSA enforcement: 
- pod-security.kubernetes.io/enforce
- pod-security.kubernetes.io/enforce-version 
- pod-security.kubernetes.io/audit 
- pod-security.kubernetes.io/audit-version 
- pod-security.kubernetes.io/warn
- pod-security.kubernetes.io/warn-version

## Secret 

### Validation Checks

A secret cannot be deleted if its deletion request has an orphan policy,
and the secret has roles or role bindings dependent on it.

### Mutation Checks

#### On create

For all secrets of type `provisioning.cattle.io/cloud-credential`, 
places a `field.cattle.io/creatorId` annotation with the name of the user as the value.

#### On delete

Checks if there are any RoleBindings owned by this secret which provide access to a role granting access to this secret.
If yes, the webhook redacts the role, so that it only grants a deletion permission.

# management.cattle.io/v3 

## ClusterRoleTemplateBinding 

### Validation Checks

#### Escalation Prevention

Users can only create/update ClusterRoleTemplateBindings which grant permissions to RoleTemplates with rights less than or equal to those they currently possess. This is to prevent privilege escalation.
For external RoleTemplates (RoleTemplates with `external` set to `true`), if the `external-rules` feature flag is enabled and `ExternalRules` is specified in the roleTemplate in `RoleTemplateName`,
`ExternalRules` will be used for authorization. Otherwise (if the feature flag is off or `ExternalRules` are nil), the rules from the backing `ClusterRole` in the local cluster will be used.

#### Invalid Fields - Create

Users cannot create ClusterRoleTemplateBindings which violate the following constraints:
- Either a user subject (through `UserName` or `UserPrincipalName`) or a group subject (through `GroupName` or `GroupPrincipalName`) must be specified; both a user subject and a group subject cannot be specified
- `ClusterName` must be specified
- The roleTemplate indicated in `RoleTemplateName` must be:
  - Provided as a non-empty value
  - Valid (i.e. is an existing `roleTemplate` object of given name in the `management.cattle.io/v3` API group)
  - Not locked (i.e. `roleTemplate.Locked` must be `false`)
  - Associated with its appropriate context (`roleTemplate.Context` must be equal to "cluster")

#### Invalid Fields - Update

Users cannot update the following fields after creation:
- RoleTemplateName
- ClusterName

Users can update the following fields if they have not been set, but after they have been set they cannot be changed:
- UserName
- UserPrincipalName
- GroupName
- GroupPrincipalName

In addition, as in the create validation, both a user subject and a group subject cannot be specified.

## Feature 

### Validation Checks

#### On update

The desired value must not change on new spec unless it's equal to the `lockedValue` or `lockedValue` is nil.
Due to the security impact of the `external-rules` feature flag, only users with admin permissions (`*` verbs on `*` resources in `*` APIGroups in all namespaces) can enable or disable this feature flag.

## GlobalRole 

### Validation Checks

Note: all checks are bypassed if the GlobalRole is being deleted.

#### Invalid Fields - Create and Update
When a GlobalRole is created or updated, the webhook checks that each rule has at least one verb.

#### Escalation Prevention

Users can only change GlobalRoles with rights less than or equal to those they currently possess. This is to prevent privilege escalation. 

## GlobalRoleBinding 

### Validation Checks

Note: all checks are bypassed if the GlobalRoleBinding is being deleted.

#### Escalation Prevention

Users can only create/update GlobalRoleBindings with rights less than or equal to those they currently possess. This is to prevent privilege escalation. 

#### Valid Global Role Reference

GlobalRoleBindings must refer to a valid global role (i.e. an existing `GlobalRole` object in the `management.cattle.io/v3` apiGroup).

## NodeDriver 

### Validation Checks

Note: checks only run if a node driver is being disabled or deleted

#### Machine Deletion Prevention

This admission webhook prevents the disabling or deletion of a NodeDriver if there are any Nodes that are under management by said driver. If there are _any_ nodes that use the driver the request will be denied.

## ProjectRoleTemplateBinding 

### Validation Checks

#### Escalation Prevention

Users can only create/update ProjectRoleTemplateBindings with rights less than or equal to those they currently possess.
This is to prevent privilege escalation.
For external RoleTemplates (RoleTemplates with `external` set to `true`), if the `external-rules` feature flag is enabled and `ExternalRules` is specified in the roleTemplate in `RoleTemplateName`,
`ExternalRules` will be used for authorization. Otherwise, if `ExternalRules` are nil when the feature flag is on, the rules from the backing `ClusterRole` in the local cluster will be used.

#### Invalid Fields - Create

Users cannot create ProjectRoleTemplateBindings that violate the following constraints:

- Either a user subject (through `UserName` or `UserPrincipalName`), or a group subject (through `GroupName`
  or `GroupPrincipalName`), or a service account subject (through `ServiceAccount`) must be specified. Exactly one
  subject type of the three must be provided.
- `ProjectName` must be specified
- The roleTemplate indicated in `RoleTemplateName` must be:
    - Provided as a non-empty value
    - Valid (there must exist a `roleTemplate` object of given name in the `management.cattle.io/v3` API group)
    - Not locked (`roleTemplate.Locked` must be `false`)
    - Associated with its appropriate context (`roleTemplate.Context` must be equal to "project")

#### Invalid Fields - Update

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

## RoleTemplate 

### Validation Checks

Note: all checks are bypassed if the RoleTemplate is being deleted

####  Circular Reference

Circular references to a `RoleTemplate` (a inherits b, b inherits a) are not allowed. More specifically, if "roleTemplate1" is included in the `roleTemplateNames` of "roleTemplate2", then "roleTemplate2" must not be included in the `roleTemplateNames` of "roleTemplate1". This check prevents the creation of roles whose end-state cannot be resolved.

#### Rules Without Verbs 

Rules without verbs, resources, or apigroups are not permitted. The `rules` and `externalRules` included in a RoleTemplate are of the same type as the rules used by standard Kubernetes RBAC types (such as `Roles` from `rbac.authorization.k8s.io/v1`). Because of this, they inherit the same restrictions as these types, including this one.

#### Escalation Prevention

Users can only change RoleTemplates with rights less than or equal to those they currently possess. This prevents privilege escalation. 
Users can't create external RoleTemplates (or update existing RoleTemplates) with `ExternalRules` without having the `escalate` verb on that RoleTemplate.

#### Context Validation

The `roletemplates.context` field must be one of the following values [`"cluster"`, `"project"`, `""`].
If the `roletemplates.administrative` is set to true the context must equal `"cluster"`.

#### Builtin Validation

The `roletemplates.builtin` field is immutable, and new builtIn RoleTemplates cannot be created.

If `roletemplates.builtin` is true then all fields are immutable except:
- `metadata` 
- `clusterCreatorDefault` 
- `projectCreatorDefault`
- `locked`

 ### Deletion check

RoleTemplate can not be deleted if they are referenced by other RoleTemplates via `roletemplates.roleTemplateNames`

## Setting 

### Validation Checks

#### Invalid Fields - Create

When a Setting is created, the following checks take place:

- If set, `disable-inactive-user-after` must be zero or a positive duration (e.g. `240h`).
- If set, `delete-inactive-user-after` must be zero or a positive duration (e.g. `240h`).
- If set, `user-last-login-default` must be a date time according to RFC3339 (e.g. `2023-11-29T00:00:00Z`).
- If set, `user-retention-cron` must be a valid standard cron expression (e.g. `0 0 * * 0`).

#### Invalid Fields - Update

When a Setting is updated, the following checks take place:

- If set, `disable-inactive-user-after` must be zero or a positive duration (e.g. `240h`).
- If set, `delete-inactive-user-after` must be zero or a positive duration (e.g. `240h`).
- If set, `user-last-login-default` must be a date time according to RFC3339 (e.g. `2023-11-29T00:00:00Z`).
- If set, `user-retention-cron` must be a valid standard cron expression (e.g. `0 0 * * 1`).

## UserAttribute 

### Validation Checks

#### Invalid Fields - Create

When a UserAttribute is created, the following checks take place:

- If set, `lastLogin` must be a valid date time according to RFC3339 (e.g. `2023-11-29T00:00:00Z`).
- If set, `disableAfter` must be zero or a positive duration (e.g. `240h`).
- If set, `deleteAfter` must be zero or a positive duration (e.g. `240h`).

#### Invalid Fields - Update

When a UserAttribute is updated, the following checks take place:

- If set, `lastLogin` must be a valid date time according to RFC3339 (e.g. `2023-11-29T00:00:00Z`).
- If set, `disableAfter` must be zero or a positive duration (e.g. `240h`).
- If set, `deleteAfter` must be zero or a positive duration (e.g. `240h`).
