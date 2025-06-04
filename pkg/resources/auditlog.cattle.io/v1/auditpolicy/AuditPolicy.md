## Validation Checks

### Invalid Fields - Create

Users cannot create an `AuditPolicy` which violates the following constraints:

- `.Spec.Filters[].Action` must be one of `allow` or `deny`
- `.Spec.Filters[].RequestURI` must be valid regex
- `.Spec.AdditionalRedactions[].Headers[]` must be valid regez
- `.Spec.AdditionalRedactions[].Paths[]` must be valid jsonpath

### Invalid Fields - Update

Users cannot update an `AuditPolicy` which violates the following constraints:

- `.Spec.Filters[].Action` must be one of `allow` or `deny`
- `.Spec.Filters[].RequestURI` must be valid regex
- `.Spec.AdditionalRedactions[].Headers[]` must be valid regez
- `.Spec.AdditionalRedactions[].Paths[]` must be valid jsonpath