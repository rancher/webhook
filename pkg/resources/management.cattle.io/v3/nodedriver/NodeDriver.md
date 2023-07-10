## Validation Checks

Note: checks only run if a node driver is being disabled or deleted

### Machine Deletion Prevention

This admission webhook prevents the disabling or deletion of a NodeDriver if there are any Nodes that are under management by said driver. If there are _any_ nodes that use the driver the request will be denied.
