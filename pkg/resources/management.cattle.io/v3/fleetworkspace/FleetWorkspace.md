## Validation Checks

A `FleetWorkspace` cannot be created if a namespace with the same name already exists.

## Mutation Checks

The `FleetWorkspace` mutating webhook no longer creates resources on create.
Namespace and RBAC objects are reconciled by the Rancher controller after
workspace creation.
