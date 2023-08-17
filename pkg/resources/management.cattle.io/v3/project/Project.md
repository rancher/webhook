## Validation Checks

### Protects system project

The system project cannot be deleted.

### Quota validation

Project quotas and default limits must be consistent with one another and must be sufficient for the requirements of active namespaces.

## Mutations

### On create

Adds the authz.management.cattle.io/creator-role-bindings annotation.
