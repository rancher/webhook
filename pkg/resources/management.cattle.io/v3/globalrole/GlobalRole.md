## Validation Checks

Note: all checks are bypassed if the GlobalRole is being deleted.

### Invalid Fields - Create and Update
When a GlobalRole is created or updated, the webhook checks that each rule has at least one verb.

### Escalation Prevention

Users can only change GlobalRoles with rights less than or equal to those they currently possess. This is to prevent privilege escalation. 

