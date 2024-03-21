## Validation Checks

Note: all checks are bypassed if the RoleTemplate is being deleted

###  Circular Reference

Circular references to a `RoleTemplate` (a inherits b, b inherits a) are not allowed. More specifically, if "roleTemplate1" is included in the `roleTemplateNames` of "roleTemplate2", then "roleTemplate2" must not be included in the `roleTemplateNames` of "roleTemplate1". This check prevents the creation of roles whose end-state cannot be resolved.

### Rules Without Verbs, Resources, API groups

Rules without verbs, resources, or apigroups are not permitted. The `rules` included in a RoleTemplate are of the same type as the rules used by standard Kubernetes RBAC types (such as `Roles` from `rbac.authorization.k8s.io/v1`). Because of this, they inherit the same restrictions as these types, including this one.

### Escalation Prevention

Users can only change RoleTemplates with rights less than or equal to those they currently possess. This prevents privilege escalation. 

### Context Validation

The `roletemplates.context` field must be one of the following values [`"cluster"`, `"project"`, `""`].
If the `roletemplates.administrative` is set to true the context must equal `"cluster"`.

### Builtin Validation

The `roletemplates.builtin` field is immutable, and new builtIn RoleTemplates cannot be created.

If `roletemplates.builtin` is true then all fields are immutable except:
- `metadata` 
- `clusterCreatorDefault` 
- `projectCreatorDefault`
- `locked`

 ### Deletion check

RoleTemplate can not be deleted if they are referenced by other RoleTemplates via `roletemplates.roleTemplateNames` or by GlobalRoles via `globalRoles.inheritedClusterRoles`
