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

## ClusterProxyConfig 

### Validation Checks

#### On create

When creating a clusterproxyconfig, we check to make sure that one does not already exist for the given cluster.
Only 1 clusterproxyconfig per downstream cluster is ever permitted.

## ClusterRoleTemplateBinding 

### Validation Checks

#### Escalation Prevention

Users can only create/update ClusterRoleTemplateBindings which grant permissions to RoleTemplates with rights less than or equal to those they currently possess. This is to prevent privilege escalation.
For external RoleTemplates (RoleTemplates with `external` set to `true`), if the `external-rules` feature flag is enabled and `ExternalRules` is specified in the roleTemplate in `RoleTemplateName`,
`ExternalRules` will be used for authorization. Otherwise (if the feature flag is off or `ExternalRules` are nil), the rules from the backing `ClusterRole` in the local cluster will be used.

#### Invalid Fields - Create

Users cannot create ClusterRoleTemplateBindings which violate the following constraints:
- Either a user subject (through `UserName` or `UserPrincipalName`) or a group subject (through `GroupName` or `GroupPrincipalName`) must be specified; both a user subject and a group subject cannot be specified
- `ClusterName` must:
  - Be provided as a non-empty value
  - Match the namespace of the ClusterRoleTemplateBinding
  - Refer to an existing cluster
- The roleTemplate indicated in `RoleTemplateName` must be:
  - Provided as a non-empty value
  - Valid (i.e. is an existing `roleTemplate` object of given name in the `management.cattle.io/v3` API group)
  - Not locked (i.e. `roleTemplate.Locked` must be `false`)
  - Associated with its appropriate context (`roleTemplate.Context` must be equal to "cluster")
- If the label indicating ownership by a GlobalRoleBinding (`authz.management.cattle.io/grb-owner`) exists, it must refer to a valid (existing and not deleting) GlobalRoleBinding

#### Invalid Fields - Update

Users cannot update the following fields after creation:
- RoleTemplateName
- ClusterName
- The label indicating ownership by a GlobalRoleBinding (`authz.management.cattle.io/grb-owner`)

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

## FleetWorkspace 

### Validation Checks

A `FleetWorkspace` cannot be created if a namespace with the same name already exists.

### Mutation Checks

#### On create

When a `FleetWorkspace` is created, it will create the following resources:
1. `Namespace`. It will have the same name as the `FleetWorkspace`.
2. `ClusterRole`. It will create the cluster role that has * permission only to the current workspace.
3. Two `RoleBindings` to bind the current user to fleet-admin roles and `FleetWorkspace` roles.

## GlobalRole 

### Validation Checks

Note: all checks are bypassed if the GlobalRole is being deleted, or if only the metadata fields are being updated.

#### Invalid Fields - Create and Update

On create or update, the following checks take place:
- The webhook validates each rule using the standard Kubernetes RBAC checks (see next section).
- Each new RoleTemplate referred to in `inheritedClusterRoles` must have a context of `cluster` and not be `locked`. This validation is skipped for RoleTemplates in `inheritedClusterRoles` for the prior version of this object.

#### Rules Without Verbs, Resources, API groups

Rules without verbs, resources, or apigroups are not permitted. The `rules` included in a GlobalRole are of the same type as the rules used by standard Kubernetes RBAC types (such as `Roles` from `rbac.authorization.k8s.io/v1`). Because of this, they inherit the same restrictions as these types, including this one.

#### Escalation Prevention

 Escalation checks are bypassed if a user has the `escalate` verb on the GlobalRole that they are attempting to update or create. This can also be given through a wildcard permission (i.e. the `*` verb also gives `escalate`).

Users can only change GlobalRoles with rights less than or equal to those they currently possess. This is to prevent privilege escalation. This includes the rules in the RoleTemplates referred to in `inheritedClusterRoles` and the rules in `inheritedFleetWorkspacePermissions`.

Users can only grant rules in the `NamespacedRules` field with rights less than or equal to those they currently possess. This works on a per namespace basis, meaning that the user must have the permission
in the namespace specified. The `Rules` field apply to every namespace, which means a user can create `NamespacedRules` in any namespace that are equal to or less than the `Rules` they currently possess.

#### Builtin Validation

The `globalroles.builtin` field is immutable, and new builtIn GlobalRoles cannot be created.
If `globalroles.builtin` is true then all fields are immutable except  `metadata` and `newUserDefault`.
If `globalroles.builtin` is true then the GlobalRole can not be deleted.

## GlobalRoleBinding 

### Validation Checks

Note: all checks are bypassed if the GlobalRoleBinding is being deleted, or if only the metadata fields are being updated.

#### Escalation Prevention

Users can only create/update GlobalRoleBindings with rights less than or equal to those they currently possess. This is to prevent privilege escalation. 

#### Valid Global Role Reference

GlobalRoleBindings must refer to a valid global role (i.e. an existing `GlobalRole` object in the `management.cattle.io/v3` apiGroup).

This escalation check is bypassed if a user has the `bind` verb on the GlobalRole that they are trying to bind to (through creating or updating a GlobalRoleBinding to that GlobalRole). This can also be given through a wildcard permission (i.e. the `*` verb also gives `bind`).

#### Invalid Fields - Update
Users cannot update the following fields after creation:
- `userName`
- `groupPrincipalName`
- `globalRoleName`


#### Invalid Fields - Create
GlobalRoleBindings must have either `userName` or `groupPrincipalName`, but not both.
All RoleTemplates which are referred to in the `inheritedClusterRoles` field must exist and not be locked. 

### Mutation Checks

#### On create

When a GlobalRoleBinding is created an owner reference is created on the binding referring to the backing GlobalRole defined by `globalRoleName`.

## NodeDriver 

### Validation Checks

Note: checks only run if a node driver is being disabled or deleted

#### Machine Deletion Prevention

This admission webhook prevents the disabling or deletion of a NodeDriver if there are any Nodes that are under management by said driver. If there are _any_ nodes that use the driver the request will be denied.

## Project 

### Validation Checks

#### ClusterName validation

ClusterName must be equal to the namespace, and must refer to an existing management.cattle.io/v3.Cluster object. In addition, users cannot update the field after creation. 

#### Protects system project

The system project cannot be deleted.

#### Quota validation

Project quotas and default limits must be consistent with one another and must be sufficient for the requirements of active namespaces.

#### Container default resource limit validation

Validation mimics the upstream behavior of the Kubernetes API server when it validates LimitRanges.
The container default resource configuration must have properly formatted quantities for all requests and limits.

Limits for any resource must not be less than requests.

### Mutations

#### On create

Adds the authz.management.cattle.io/creator-role-bindings annotation.

## ProjectRoleTemplateBinding 

### Validation Checks

#### Escalation Prevention

Users can only create/update ProjectRoleTemplateBindings with rights less than or equal to those they currently possess.
This is to prevent privilege escalation.
For external RoleTemplates (RoleTemplates with `external` set to `true`), if the `external-rules` feature flag is enabled and `ExternalRules` is specified in the roleTemplate in `RoleTemplateName`,
`ExternalRules` will be used for authorization. Otherwise, if `ExternalRules` are nil when the feature flag is on, the rules from the backing `ClusterRole` in the local cluster will be used.

#### Invalid Fields - Create

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

#### Rules Without Verbs, Resources, API groups

Rules without verbs, resources, or apigroups are not permitted. The `rules` and `externalRules` included in a RoleTemplate are of the same type as the rules used by standard Kubernetes RBAC types (such as `Roles` from `rbac.authorization.k8s.io/v1`). Because of this, they inherit the same restrictions as these types, including this one.

#### Escalation Prevention

Users can only change RoleTemplates with rights less than or equal to those they currently possess. This prevents privilege escalation. 
Users can't create external RoleTemplates (or update existing RoleTemplates) with `ExternalRules` without having the `escalate` verb on that RoleTemplate.

#### Context Validation

The `roletemplates.context` field must be one of the following values [`"cluster"`, `"project"`, `""`].
If the `roletemplates.administrative` is set to true the context must equal `"cluster"`.

If the `roletemplate.ProjectCreatorDefault` is true, context must equal `"project"`
#### Builtin Validation

The `roletemplates.builtin` field is immutable, and new builtIn RoleTemplates cannot be created.

If `roletemplates.builtin` is true then all fields are immutable except:
- `metadata` 
- `clusterCreatorDefault` 
- `projectCreatorDefault`
- `locked`

 ### Deletion check

RoleTemplate can not be deleted if they are referenced by other RoleTemplates via `roletemplates.roleTemplateNames` or by GlobalRoles via `globalRoles.inheritedClusterRoles`

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

# rbac.authorization.k8s.io/v1 

## ClusterRole 

### Validation Checks

#### Invalid Fields - Update
Users cannot update or remove the following label after it has been added:
- authz.management.cattle.io/gr-owner

## ClusterRoleBinding 

### Validation Checks

#### Invalid Fields - Update
Users cannot update or remove the following label after it has been added:
- authz.management.cattle.io/grb-owner

## Role 

### Validation Checks

#### Invalid Fields - Update
Users cannot update or remove the following label after it has been added:
- authz.management.cattle.io/gr-owner

## RoleBinding 

### Validation Checks

#### Invalid Fields - Update
Users cannot update or remove the following label after it has been added:
- authz.management.cattle.io/grb-owner
