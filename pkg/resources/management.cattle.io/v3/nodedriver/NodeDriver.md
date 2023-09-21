## Validation Checks

Note: validation runs for node driver create, update, and delete operations

### Machine Deletion Prevention

This admission webhook prevents the disabling or deletion of a NodeDriver if there are any Nodes that are under management by said driver. If there are _any_ nodes that use the driver the request will be denied.

### Name Validation

This admission webhook sanitizes the names of the NodeDriver since that name will be used in generating a Dynamic Schema.
