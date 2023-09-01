## Validation Checks

Note: all checks are bypassed if the GlobalRole is being deleted, or if only the metadata fields are being updated.

### Invalid Fields - Create and Update

On create or update, the following checks take place:
- The webhook checks that each rule has at least one verb.
- Each new RoleTemplate referred to in `inheritedClusterRoles` must have a context of `cluster` and not be `locked`. This validation is skipped for RoleTemplates in `inheritedClusterRoles` for the prior version of this object.

### Escalation Prevention

Users can only change GlobalRoles with rights less than or equal to those they currently possess. This is to prevent privilege escalation. This includes the rules in the RoleTemplates referred to in `inheritedClusterRoles`. 

