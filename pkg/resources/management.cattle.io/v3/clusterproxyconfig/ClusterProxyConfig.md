## Validation Checks

### On create

When creating a clusterproxyconfig, we check to make sure that one does not already exist for the given cluster.
Only 1 clusterproxyconfig per downstream cluster is ever permitted.
