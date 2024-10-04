## Validation Checks

### Creator ID Annotation

The annotation `field.cattle.io/creatorId` must be set to the Username of the User that initiated the request.

The annotation `field.cattle.io/creatorId` cannot be changed, but it can be removed.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` cannot be set.

## Mutation Checks

### Creator ID Annotion

When a cluster is created `field.cattle.io/creatorId` is set to the Username from the request.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` does not get set.
