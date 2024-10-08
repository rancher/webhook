## Validation Checks

### Invalid Fields - Create

When a Token is created, the following checks take place:

- If set, `lastUsedAt` must be a valid date time according to RFC3339 (e.g. `2023-11-29T00:00:00Z`).

### Invalid Fields - Update

When a Token is updated, the following checks take place:

- If set, `lastUsedAt` must be a valid date time according to RFC3339 (e.g. `2023-11-29T00:00:00Z`).
