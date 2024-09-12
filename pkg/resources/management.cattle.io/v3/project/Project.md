## Validation Checks

### ClusterName validation

ClusterName must be equal to the namespace, and must refer to an existing `management.cattle.io/v3.Cluster` object. In addition, users cannot update the field after creation.

### Protects system project

The system project cannot be deleted.

### Quota validation

Project quotas and default limits must be consistent with one another and must be sufficient for the requirements of active namespaces.

### Container default resource limit validation

Validation mimics the upstream behavior of the Kubernetes API server when it validates LimitRanges.
The container default resource configuration must have properly formatted quantities for all requests and limits.

Limits for any resource must not be less than requests.

### Annotations validation

When a project is created if `field.cattle.io/creator-principal-name` annotation is set then `field.cattle.io/creatorId` annotation must be set as well and the user's principal name in the former should match the creator's user principal id.

## Mutations

### On create

Adds the authz.management.cattle.io/creator-role-bindings annotation.
