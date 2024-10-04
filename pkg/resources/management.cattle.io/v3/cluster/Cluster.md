## Validation Checks

### Annotations validation

When a cluster is created and `field.cattle.io/creator-principal-name` annotation is set then `field.cattle.io/creatorId` annotation must be set as well. The value of `field.cattle.io/creator-principal-name` should match the creator's user principal id.

When a cluster is updated `field.cattle.io/creator-principal-name` and `field.cattle.io/creatorId` annotations must stay the same or removed.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` cannot be set.
