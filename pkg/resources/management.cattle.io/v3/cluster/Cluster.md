## Cluster

### Annotations validation

When a cluster is created if `field.cattle.io/creator-principal-name` annotation is set then `field.cattle.io/creatorId` annotation must be set as well and the user's principal name in the former should match the creator's user principal id.

When a cluster is updated `field.cattle.io/creator-principal-name` and `field.cattle.io/creatorId` annotations must stay the same or removed.
