## Validation Checks

### On update

The desired value must not change on new spec unless it's equal to the `lockedValue` or `lockedValue` is nil.
Due to the security impact of the `external-rules` feature flag, only users with admin permissions (`*` verbs on `*` resources in `*` APIGroups in all namespaces) can enable or disable this feature flag.
