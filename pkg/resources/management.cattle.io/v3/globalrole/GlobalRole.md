## Validation Checks

Note: all checks are bypassed if the GlobalRole is being deleted, or if only the metadata fields are being updated.

### Invalid Fields - Create and Update

On create or update, the following checks take place:
- The webhook validates each rule using the standard Kubernetes RBAC checks (see next section).
- Each new RoleTemplate referred to in `inheritedClusterRoles` must have a context of `cluster` and not be `locked`. This validation is skipped for RoleTemplates in `inheritedClusterRoles` for the prior version of this object.

### Rules Without Verbs, Resources, API groups

Rules without verbs, resources, or apigroups are not permitted. The `rules` included in a GlobalRole are of the same type as the rules used by standard Kubernetes RBAC types (such as `Roles` from `rbac.authorization.k8s.io/v1`). Because of this, they inherit the same restrictions as these types, including this one.

### Escalation Prevention

 Escalation checks are bypassed if a user has the `escalate` verb on the GlobalRole that they are attempting to update or create. This can also be given through a wildcard permission (i.e. the `*` verb also gives `escalate`).

Users can only change GlobalRoles with rights less than or equal to those they currently possess. This is to prevent privilege escalation. This includes the rules in the RoleTemplates referred to in `inheritedClusterRoles` and the rules in `inheritedFleetWorkspacePermissions`.

Users can only grant rules in the `NamespacedRules` field with rights less than or equal to those they currently possess. This works on a per namespace basis, meaning that the user must have the permission
in the namespace specified. The `Rules` field apply to every namespace, which means a user can create `NamespacedRules` in any namespace that are equal to or less than the `Rules` they currently possess.

### Builtin Validation

The `globalroles.builtin` field is immutable, and new builtIn GlobalRoles cannot be created.
If `globalroles.builtin` is true then all fields are immutable except  `metadata` and `newUserDefault`.
If `globalroles.builtin` is true then the GlobalRole can not be deleted.
