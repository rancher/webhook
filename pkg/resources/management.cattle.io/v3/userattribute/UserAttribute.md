## Validation Checks

### Invalid Fields - Create

When a UserAttribute is created, the following checks take place:

- If set, `disableAfter` must be zero or a positive duration (e.g. `240h`).
- If set, `deleteAfter` must be zero or a positive duration (e.g. `240h`).

### Invalid Fields - Update

When a UserAttribute is updated, the following checks take place:

- If set, `disableAfter` must be zero or a positive duration (e.g. `240h`).
- If set, `deleteAfter` must be zero or a positive duration (e.g. `240h`).
