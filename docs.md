# core/v1 

## Namespace 

### Validation Checks

Note: The kube-system namespace, unlike other namespaces, has a "failPolicy" of "ignore" on update calls.

#### PSA Label Validation

Validates that users who create or edit a PSA enforcement label on a namespace have the `updatepsa` verb on `projects` in `management.cattle.io/v3`. See the [upstream docs](https://kubernetes.io/docs/concepts/security/pod-security-admission/) for more information on the effect of these labels.

The following labels are considered relevant labels for PSA enforcement: `"pod-security.kubernetes.io/enforce", "pod-security.kubernetes.io/enforce-version", "pod-security.kubernetes.io/audit", "pod-security.kubernetes.io/audit-version", "pod-security.kubernetes.io/warn", "pod-security.kubernetes.io/warn-version"`.

# management.cattle.io/v3 

## ClusterRoleTemplateBinding 

### Validation Checks

#### Escalation Prevention

Users can only create/update ClusterRoleTemplateBindings which grant permissions to RoleTemplates with rights less than or equal to those they currently possess. This is to prevent privilege escalation. 

#### Invalid Fields - Create

Users cannot create ClusterRoleTemplateBindings which violate the following constraints:
- Either a user subject (through "UserName" or "UserPrincipalName") or a group subject (through "GroupName" or "GroupPrincipalName") must be specified; both a user subject and group subject cannot be specified
- A "ClusterName" must be specified
- The roleTemplate indicated in "RoleTemplateName" must be:
  - Valid (i.e. is an existing `roleTemplate` object in the `management.cattle.io/v3` apiGroup)
  - Not locked (i.e. `roleTemplate.Locked` must be `false`)

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

## GlobalRole 

### Validation Checks

Note: all checks are bypassed if the GlobalRole is being deleted

#### Escalation Prevention

Users can only change GlobalRoles with rights less than or equal to those they currently possess. This is to prevent privilege escalation. 

## GlobalRoleBinding 

### Validation Checks

Note: all checks are bypassed if the GlobalRoleBinding is being deleted

#### Escalation Prevention

Users can only create/update GlobalRoleBindings with rights less than or equal to those they currently possess. This is to prevent privilege escalation. 

#### Valid Global Role Reference

GlobalRoleBindings must refer to a valid global role (i.e. an existing `GlobalRole` object in the `management.cattle.io/v3` apiGroup).

## ProjectRoleTemplateBinding 

### Validation Checks

#### Escalation Prevention

Users can only create/update ProjectRoleTemplateBindings with rights less than or equal to those they currently possess. This is to prevent privilege escalation. 

#### Invalid Fields - Create

Users cannot create ProjectRoleTemplateBindings which violate the following constraints:
- Either a user subject (through "UserName" or "UserPrincipalName") or a group subject (through "GroupName" or "GroupPrincipalName") must be specified; both a user subject and group subject cannot be specified
- A "ProjectName" must be specified
- The roleTemplate indicated in "RoleTemplateName" must be:
  - Valid (i.e. is an existing `roleTemplate` object in the `management.cattle.io/v3` apiGroup)
  - Not locked (i.e. `roleTemplate.Locked` must be `false`)

#### Invalid Fields - Update

Users cannot update the following fields after creation:
- RoleTemplateName
- ProjectName

Users can update the following fields if they have not been set, but after they have been set they cannot be changed:
- UserName
- UserPrincipalName
- GroupName
- GroupPrincipalName

In addition, as in the create validation, both a user subject and a group subject cannot be specified.

## RoleTemplate 

### Validation Checks

Note: all checks are bypassed if the RoleTemplate is being deleted

####  Circular Reference

Circular references to webhooks (a inherits b, b inherits a) are not allowed. More specifically, if "roleTemplate1" is included in the `roleTemplateNames` of "roleTemplate2", then "roleTemplate2" must not be included in the `roleTemplateNames` of "roleTemplate1". This checks prevents the creation of roles whose end-state cannot be resolved.

#### Rules Without Verbs 

Rules without verbs are not permitted. The `rules` included in a roleTemplate are of the same type as the rules used by standard kubernetes RBAC types (such as `Roles` from `rbac.authorization.k8s.io/v1`). Because of this, they inherit the same restrictions as these types, including this one.

#### Escalation Prevention

Users can only change RoleTemplates with rights less than or equal to those they currently possess. This prevents privilege escalation. 
