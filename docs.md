# auditlog.cattle.io/v1

## AuditPolicy

### Validation Checks

#### Invalid Fields - Create

Users cannot create an `AuditPolicy` which violates the following constraints:

- `.Spec.Filters[].Action` must be one of `allow` or `deny`
- `.Spec.Filters[].RequestURI` must be valid regex
- `.Spec.AdditionalRedactions[].Headers[]` must be valid regez
- `.Spec.AdditionalRedactions[].Paths[]` must be valid jsonpath

#### Invalid Fields - Update

Users cannot update an `AuditPolicy` which violates the following constraints:

- `.Spec.Filters[].Action` must be one of `allow` or `deny`
- `.Spec.Filters[].RequestURI` must be valid regex
- `.Spec.AdditionalRedactions[].Headers[]` must be valid regez
- `.Spec.AdditionalRedactions[].Paths[]` must be valid jsonpath

# catalog.cattle.io/v1

## ClusterRepo

### Validation Checks

#### Invalid Fields - Create

Users cannot create a ClusterRepo which violates the following constraints:

- Fields GitRepo and URL are mutually exclusive and so both cannot be filled at once.

#### Invalid Fields - Update

Users cannot update a ClusterRepo which violates the following constraints:

- Fields GitRepo and URL are mutually exclusive and so both cannot be filled at once.

# cluster.cattle.io/v3

## ClusterAuthToken

### Validation Checks

#### Invalid Fields - Create

When a ClusterAuthToken is created, the following checks take place:

- If set, `lastUsedAt` must be a valid date time according to RFC3339 (e.g. `2023-11-29T00:00:00Z`).

#### Invalid Fields - Update

When a ClusterAuthToken is updated, the following checks take place:

- If set, `lastUsedAt` must be a valid date time according to RFC3339 (e.g. `2023-11-29T00:00:00Z`).

# cluster.x-k8s.io/v1beta1

## Scale

### cluster.x-k8s.io/v1beta1

#### MachineDeployment

##### Validation Checks

###### On Create and Update

When a scale operation is performed on a MachineDeployment, the webhook synchronizes the replica count between the MachineDeployment and its corresponding machine pool in the Rancher provisioning cluster if it exists.

**Synchronization Flow:**

1. **Early Exit** - Skip synchronization if:
   - Dry-run request is detected
   - MachineDeployment doesn't exist
   - Required labels are missing (`cluster.x-k8s.io/cluster-name` or `rke.cattle.io/rke-machine-pool-name`)

2. **Cluster Resolution:**
   - Extracts the CAPI cluster name from the `cluster.x-k8s.io/cluster-name` label
   - Extracts the Rancher machine pool name from the `rke.cattle.io/rke-machine-pool-name` label
   - Retrieves the CAPI Cluster object using the cluster name label
   - Finds the Rancher Provisioning Cluster by checking owner references on the CAPI Cluster

3. **Machine Pool Matching:**
   - Validates the provisioning Cluster has RKEConfig and MachinePools configured
   - Locates the matching machine pool by name in the provisioning Cluster's RKEConfig
   - If not found, skips synchronization (no error)

4. **Replica Synchronization:**
   - Compares the replica count from the scale request with the machine pool's quantity
   - If they differ, updates the machine pool's quantity to match the scale request
   - Uses exponential backoff retry for update operations

**Error Handling:**
- Missing MachineDeployment: Admits the scale operation (not an error)
- Missing labels: Skips synchronization silently
- Missing CAPI Cluster: Admits the scale operation (not an error)
- Missing Provisioning Cluster: Admits the scale operation (not an error)
- Missing RKEConfig/MachinePools: Skips synchronization silently
- Machine pool not found: Skips synchronization silently
- Update failures: Returns error with escalation flag

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

#### Namespace resource limit validation

Validation ensures that the limits for cpu/memory must not be less than the requests for cpu/memory.

## Secret

### Validation Checks

A secret cannot be deleted if its deletion request has an orphan policy,
and the secret has roles or role bindings dependent on it.

### Mutation Checks

#### On create

For all secrets of type `provisioning.cattle.io/cloud-credential`, 
places a `field.cattle.io/creatorId` annotation with the name of the user as the value.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` does not get set.

For secrets stored in the `cattle-local-user-passwords` namespace containing local users passwords:
- Verifies the password has the minimum required length.
- Verifies the password is not the same as the username.
- Encrypts the password using pbkdf2.

#### On delete

Checks if there are any RoleBindings owned by this secret which provide access to a role granting access to this secret.
If yes, the webhook redacts the role, so that it only grants a deletion permission.

# management.cattle.io/v3

## Authconfig


### Validation Checks

#### Create and Update

When an LDAP (`openldap`, `freeipa`) or ActiveDirectory (`activedirectory`) authconfig is created or updated, the following checks take place:

- The field `servers` is required.
- If set, the following fields should have valid LDAP attribute names according to RFC4512
  - `userSearchAttribute`
  - `userLoginAttribute`
  - `userObjectClass`
  - `userNameAttribute`
  - `userMemberAttribute` (only for LDAP authconfigs)
  - `userEnabledAttribute`
  - `groupSearchAttribute`
  - `groupObjectClass`
  - `groupNameAttribute`
  - `groupDNAttribute`
  - `groupMemberUserAttribute`
  - `groupMemberMappingAttribute`
- If set, the following fields should have a valid LDAP filter expression according to RFC4515
  - `userLoginFilter`
  - `userSearchFilter`
  - `groupSearchFilter`

## Cluster


### Mutation Checks

##### Feature: version management on imported RKE2/K3s cluster 

- When a cluster is created or updated, add the `rancher.io/imported-cluster-version-management: system-default` annotation if the annotation is missing or its value is an empty string.


### Validation Checks

#### Annotations validation

When a cluster is created and `field.cattle.io/creator-principal-name` annotation is set then `field.cattle.io/creatorId` annotation must be set as well. The value of `field.cattle.io/creator-principal-name` should match the creator's user principal id.

When a cluster is updated `field.cattle.io/creator-principal-name` and `field.cattle.io/creatorId` annotations must stay the same or removed.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` cannot be set.


##### Feature: version management on imported RKE2/K3s cluster

 - When a cluster is created or updated, the `rancher.io/imported-cluster-version-management` annotation must be set with a valid value (true, false, or system-default). 
 - If the cluster represents other types of clusters and the annotation is present, the webhook will permit the request with a warning that the annotation is intended for imported RKE2/k3s clusters and will not take effect on this cluster.
 - If version management is determined to be disabled, and the `.spec.rke2Config` or `.spec.k3sConfig` field exists in the new cluster object with a value different from the old one, the webhook will permit the update with a warning indicating that these changes will not take effect until version management is enabled for the cluster.
 - If version management is determined to be disabled, and the `.spec.rke2Config` or `.spec.k3sConfig` field is missing, the webhook will permit the request to allow users to remove the unused fields via API or Terraform.


##### Feature: Cluster Agent Scheduling Customization

The `SchedulingCustomization` subfield of the `DeploymentCustomization` field defines the properties of a Pod Disruption Budget and Priority Class which will be automatically deployed by Rancher for the cattle-cluster-agent.

The `schedulingCustomization.PriorityClass` field contains two attributes

+ `value`: This must be an integer value equal to or between negative 1 billion and 1 billion.
+ `preemptionPolicy`: This must be a string value which indicates the desired preemption behavior, its value can be either `PreemptLowerPriority` or `Never`. Any other value must be rejected.

The `schedulingCustomization.PodDisruptionBudget` field contains two attributes

+ `minAvailable`: This is a string value that indicates the minimum number of agent replicas that must be running at a given time.
+ `maxUnavailable`: This is a string value that indicates the maximum number of agent replicas that can be unavailable at a given time.

Both `minAvailable` and `maxUnavailable` must be a string which represents a non-negative whole number, or a whole number percentage greater than or equal to `0%` and less than or equal to `100%`. Only one of the two fields can have a non-zero or empty value at a given time. These fields use the following regex when assessing if a given percentage value is valid:
```regex
^([0-9]|[1-9][0-9]|100)%$
```

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

#### Duplicate ClusterRoleTemplateBinding Prevention

On creation, the webhook prevents the creation of a `ClusterRoleTemplateBinding` if another one already exists with the same subject and role in the same cluster. 
This ensures that a user or group is not granted the same cluster-level role multiple times.

A binding is considered a duplicate if another `ClusterRoleTemplateBinding` exists with the exact same values for:
- `clusterName`
- `roleTemplateName`
- The subject, which is determined by one of the following fields:
  - `userName`
  - `userPrincipalName`
  - `groupName`
  - `groupPrincipalName`

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
- `userPrincipalName`
- `groupPrincipalName`
- `globalRoleName`


#### Invalid Fields - Create
GlobalRoleBindings must have one of `userName`, `userPrincipalName` or `groupPrincipalName` but not all.
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

ClusterName must be equal to the namespace, and must refer to an existing `management.cattle.io/v3.Cluster` object. In addition, users cannot update the field after creation.

#### BackingNamespace validation
The BackingNamespace field cannot be changed once set. Projects without the BackingNamespace field can have it added.

#### Protects system project

The system project cannot be deleted.

#### Quota validation

Project quotas and default limits must be consistent with one another and must be sufficient for the requirements of active namespaces.

#### Container default resource limit validation

Validation mimics the upstream behavior of the Kubernetes API server when it validates LimitRanges.
The container default resource configuration must have properly formatted quantities for all requests and limits.

Limits for any resource must not be less than requests.

#### Annotations validation

When a project is created and `field.cattle.io/creator-principal-name` annotation is set then `field.cattle.io/creatorId` annotation must be set as well. The value of `field.cattle.io/creator-principal-name` should match the creator's user principal id.

When a project is updated `field.cattle.io/creator-principal-name` and `field.cattle.io/creatorId` annotations must stay the same or removed.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` cannot be set.

### Mutations

#### On create

Populates the BackingNamespace field by concatenating `Project.ClusterName` and `Project.Name`.

If the project is using a generated name (ie `GenerateName` is not empty), the generation happens within the mutating webhook.
The reason for this is that the BackingNamespace is made up of the `Project.Name`, and name generation happens after mutating webhooks and before validating webhooks.

Adds the authz.management.cattle.io/creator-role-bindings annotation.

#### On update

If the BackingNamespace field is empty, populate the BackingNamespace field with the project name.

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

#### Create and Update

When settings are created or updated, the following common checks take place:

- If set, `disable-inactive-user-after` must be zero or a positive duration (e.g. `240h`).
- If set, `delete-inactive-user-after` must be zero or a positive duration and can't be less than `336h` (e.g. `336h`).
- If set, `user-last-login-default` must be a date time according to RFC3339 (e.g. `2023-11-29T00:00:00Z`).
- If set, `user-retention-cron` must be a valid standard cron expression (e.g. `0 0 * * 0`).
- The `auth-user-session-ttl-minutes` must be a positive integer and can't be greater than `disable-inactive-user-after` or `delete-inactive-user-after` if those values are set.
- The `auth-user-session-idle-ttl-minutes` must be a positive integer and can't be greater than `auth-user-session-ttl-minutes`.

#### Update

When settings are updated, the following additional checks take place:

- If `agent-tls-mode` has `default` or `value` updated from `system-store` to `strict`, then all non-local clusters must
  have a status condition `AgentTlsStrictCheck` set to `True`, unless the new setting has an overriding
  annotation `cattle.io/force=true`.


- `cluster-agent-default-priority-class` and `fleet-agent-default-priority-class` must contain a valid JSON object which matches the format of a `v1.PriorityClassSpec` object. The Value field must be greater than or equal to negative 1 billion and less than or equal to 1 billion. The Preemption field must be a string value set to either `PreemptLowerPriority` or `Never`.


- `cluster-agent-default-pod-disruption-budget` and `fleet-agent-default-pod-disruption-budget` must contain a valid JSON object which matches the format of a `v1.PodDisruptionBudgetSpec` object. The `minAvailable` and `maxUnavailable` fields must have a string value that is either a non-negative whole number, or a non-negative whole number percentage value less than or equal to `100%`.

## Token

### Validation Checks

#### Invalid Fields - Create

When a Token is created, the following checks take place:

- If set, `lastUsedAt` must be a valid date time according to RFC3339 (e.g. `2023-11-29T00:00:00Z`).

#### Invalid Fields - Update

When a Token is updated, the following checks take place:

- If set, `lastUsedAt` must be a valid date time according to RFC3339 (e.g. `2023-11-29T00:00:00Z`).

## User

### Validation Checks

#### Create and Delete

Verifies there aren't any other users with the same username.

#### Update and Delete

When a user is updated or deleted, a check occurs to ensure that the user making the request has permissions greater than or equal to the user being updated or deleted. To get the user's groups, the user's UserAttributes are checked. This is best effort, because UserAttributes are only updated when a User logs in, so it may not be perfectly up to date.

If the user making the request has the verb `manage-users` for the resource `users`, then it is allowed to bypass the check. Note that the wildcard `*` includes the `manage-users` verb.

#### Invalid Fields - Update

Users can update the following fields if they had not been set. But after getting initial values, the fields cannot be changed:

- UserName

A user can't deactivate or delete himself.

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

# provisioning.cattle.io/v1

## Cluster

### Validation Checks

#### On Create

##### Creator ID Annotation

The annotation `field.cattle.io/creatorId` must be set to the Username of the User that initiated the request.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` cannot be set.

##### NO_PROXY value

Prevent the creation of new objects with an env var (under `spec.agentEnvVars`) with a name of `NO_PROXY` if its value contains one or more spaces. This ensures that the provided value adheres to
the format expected by Go, and helps to prevent subtle issues elsewhere when writing scripts which utilize `NO_PROXY`.  

##### Data Directories

Prevent the creation of new objects with an env var (under `spec.agentEnvVars`) with a name of `CATTLE_AGENT_VAR_DIR`.
Prevent the creation of new objects with an invalid data directory. An invalid data directory is defined as the 
following:
- Is not an absolute path (i.e. does not start with `/`)
- Attempts to include environment variables (e.g. `$VARIABLE` or `${VARIABLE}`)
- Attempts to include shell expressions (e.g. `$(command)` or `` `command` ``)
- Equal to another data directory
- Attempts to nest another data directory

If the action is an update, and the old cluster had a `nil` `.spec.rkeConfig`, accept the request, since this is how rancherd operates, and is required for harvester installations.

##### Etcd S3 CloudCredential Secret

Prevent the creation of objects if the secret specified in `.spec.rkeConfig.etcd.s3.cloudCredentialName` does not exist.

#### On Update

##### Creator ID Annotation

The annotation `field.cattle.io/creatorId` cannot be changed, but it can be removed.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` cannot be set.

##### RKEConfig changed

The `spec.rkeConfig` field cannot be changed from `nil`/ not `nil` after creation.

The local cluster is an exemption, as the rancherd use case allows managing the local cluster via this mechanism.

##### Data Directories

On update, prevent new env vars with this name from being added but allow them to be removed. Rancher will perform 
a one-time migration to move the system-agent data dir definition to the top level field from the `AgentEnvVars` 
section. A secondary validator will ensure that the effective data directory for the `system-agent` is not different 
from the one chosen during cluster creation. Additionally, the changing of a data directory for the `system-agent`, 
kubernetes distro (RKE2/K3s), and CAPR components is also prohibited.

##### cluster.spec.clusterAgentDeploymentCustomization and cluster.spec.fleetAgentDeploymentCustomization

The `DeploymentCustomization` fields are of 3 types:
- `appendTolerations`: adds tolerations to the appropriate deployment (cluster-agent/fleet-agent)
- `affinity`: adds various affinities to the deployments, which include the following
  - `nodeAffinity`: where to schedule the workload
  - `podAffinitity` and `podAntiAffinity`: pods to avoid or prefer when scheduling the workload

A `Toleration` is matched to a regex which is provided by upstream [apimachinery here](https://github.com/kubernetes/apimachinery/blob/02a41040d88da08de6765573ae2b1a51f424e1ca/pkg/apis/meta/v1/validation/validation.go#L96) but it boils down to this regex on the label:
```regex
([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]
```

For the `Affinity` based rules, the `podAffinity`/`podAntiAffinity` are validated via label selectors via [this apimachinery function](https://github.com/kubernetes/apimachinery/blob/02a41040d88da08de6765573ae2b1a51f424e1ca/pkg/apis/meta/v1/validation/validation.go#L56) whereas the `nodeAffinity` `nodeSelectorTerms` are validated via the same `Toleration` function.

##### cluster.spec.clusterAgentDeploymentCustomization.schedulingCustomization and cluster.spec.fleetAgentDeploymentCustomization.schedulingCustomization

The `SchedulingCustomization` subfield of the `DeploymentCustomization` field defines the properties of a Pod Disruption Budget and Priority Class which will be automatically deployed by Rancher for the cattle-cluster-agent.

The `schedulingCustomization.PriorityClass` field contains two attributes

+ `value`: This must be an integer value equal to or between negative 1 billion and 1 billion.
+ `preemptionPolicy`: This must be a string value which indicates the desired preemption behavior, its value can be either `PreemptLowerPriority` or `Never`. Any other value must be rejected.

The `schedulingCustomization.PodDisruptionBudget` field contains two attributes

+ `minAvailable`: This is a string value that indicates the minimum number of agent replicas that must be running at a given time.
+ `maxUnavailable`: This is a string value that indicates the maximum number of agent replicas that can be unavailable at a given time.

Both `minAvailable` and `maxUnavailable` must be a string which represents a non-negative whole number, or a whole number percentage greater than or equal to `0%` and less than or equal to `100%`. Only one of the two fields can have a non-zero or empty value at a given time. These fields use the following regex when assessing if a given percentage value is valid:
```regex
^([0-9]|[1-9][0-9]|100)%$
```

##### NO_PROXY value

Prevent the update of objects with an env var (under `spec.agentEnvVars`) with a name of `NO_PROXY` if its value contains one or more spaces. This ensures that the provided value adheres to
the format expected by Go, and helps to prevent subtle issues elsewhere when writing scripts which utilize `NO_PROXY`.  

The only exception to this check is if the existing cluster already has a `NO_PROXY` variable which includes spaces in its value. In this case, update operations are permitted. If `NO_PROXY` is later updated to value which does not contain spaces, this exception will no longer occur.

##### Etcd S3 CloudCredential Secret

Prevent the update of objects if the secret specified in `.spec.rkeConfig.etcd.s3.cloudCredentialName` does not exist.

##### ETCD Snapshot Restore

Validation for `spec.rkeConfig.etcdSnapshotRestore` is only triggered when this field is changed to a new, non-empty value. This check is intentionally skipped if the field is unchanged, which prevents blocking unrelated cluster updates (e.g., node scaling) if the referenced snapshot is deleted *after* a successful restore.

When triggered, the following checks are performed:

* The referenced snapshot in `etcdSnapshotRestore.name` must exist in the same namespace as the cluster.
* The `etcdSnapshotRestore.restoreRKEConfig` field must be a supported mode (`"none"`, `"kubernetesVersion"`, or `"all"`).
* If `restoreRKEConfig` is **`"kubernetesVersion"`**, the snapshot's metadata must be parsable and contain a `kubernetesVersion`.
* If `restoreRKEConfig` is **`"all"`**, the snapshot's metadata must be parsable and contain both `kubernetesVersion` and `rkeConfig`.

### Mutation Checks

#### On Create

##### Creator ID Annotation

When a cluster is created `field.cattle.io/creatorId` is set to the Username from the request.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` does not get set.

#### On Update

##### Dynamic Schema Drop

Check for the presence of the `provisioning.cattle.io/allow-dynamic-schema-drop` annotation. If the value is `"true"`,
perform no mutations. If the value is not present or not `"true"`, compare the value of the `dynamicSchemaSpec` field
for each `machinePool`, to its' previous value. If the values are not identical, revert the value for the
`dynamicSchemaSpec` for the specific `machinePool`, but do not reject the request.

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

# rke-machine-config.cattle.io/v1

## MachineConfig

### Validation Checks

#### Creator ID Annotation

The annotation `field.cattle.io/creatorId` must be set to the Username of the User that initiated the request.

The annotation `field.cattle.io/creatorId` cannot be changed, but it can be removed.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` cannot be set.

### Mutation Checks

#### Creator ID Annotion

When a cluster is created `field.cattle.io/creatorId` is set to the Username from the request.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` does not get set.
