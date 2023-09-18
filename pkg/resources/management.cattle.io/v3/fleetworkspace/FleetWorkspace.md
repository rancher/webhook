## Validation Checks

A `FleetWorkspace` cannot be created if a namespace with the same name already exists.

## Mutation Checks

### On create

When a `FleetWorkspace` is created, it will create the following resources:
1. `Namespace`. It will have the same name as the `FleetWorkspace`.
2. `ClusterRole`. It will create the cluster role that has * permission only to the current workspace.
3. Two `RoleBindings` to bind the current user to fleet-admin roles and `FleetWorkspace` roles.
