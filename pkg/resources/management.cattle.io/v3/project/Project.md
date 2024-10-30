## Validation Checks

### ClusterName validation

ClusterName must be equal to the namespace, and must refer to an existing `management.cattle.io/v3.Cluster` object. In addition, users cannot update the field after creation.

### BackingNamespace validation
The `BackingNamespace` field cannot be changed once set. Projects without the `BackingNamespace` field can have it added.

### Protects system project

The system project cannot be deleted.

### Quota validation

Project quotas and default limits must be consistent with one another and must be sufficient for the requirements of active namespaces.

### Container default resource limit validation

Validation mimics the upstream behavior of the Kubernetes API server when it validates LimitRanges.
The container default resource configuration must have properly formatted quantities for all requests and limits.

Limits for any resource must not be less than requests.

### Annotations validation

When a project is created and `field.cattle.io/creator-principal-name` annotation is set then `field.cattle.io/creatorId` annotation must be set as well. The value of `field.cattle.io/creator-principal-name` should match the creator's user principal id.

When a project is updated `field.cattle.io/creator-principal-name` and `field.cattle.io/creatorId` annotations must stay the same or removed.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` cannot be set.

## Mutations

### On create

Populates the `BackingNamespace` field by concatenating `Project.ClusterName` and `Project.Name`.

If the project is using a generated name (ie `GenerateName` is not empty), the generation happens within the mutating webhook.
The reason for this is that the `BackingNamespace` is made up of the `Project.Name`, and name generation happens after mutating and before validating webhooks.

Adds the authz.management.cattle.io/creator-role-bindings annotation.

### On update

If the `BackingNamespace` field is empty, it's populated with the project name.
