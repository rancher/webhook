## Validation Checks

### Invalid Fields - Create

Users cannot create a ClusterRepo which violates the following constraints:

- Fields GitRepo and URL are mutually exclusive and so both cannot be filled at once.

### Invalid Fields - Update

Users cannot update a ClusterRepo which violates the following constraints:

- Fields GitRepo and URL are mutually exclusive and so both cannot be filled at once.
