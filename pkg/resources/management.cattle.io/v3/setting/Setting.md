## Validation Checks

### Invalid Fields - Create

When a Setting is created, the following checks take place:

- If set, `disable-inactive-user-after` must be zero or a positive duration and can't be less than `auth-user-session-ttl-minutes` (e.g. `240h`).
- If set, `delete-inactive-user-after` must be zero or a positive duration and can't be less than `336h` or `auth-user-session-ttl-minutes`, whichever is greater (e.g. `336h`).
- If set, `user-last-login-default` must be a date time according to RFC3339 (e.g. `2023-11-29T00:00:00Z`).
- If set, `user-retention-cron` must be a valid standard cron expression (e.g. `0 0 * * 0`).

### Invalid Fields - Update

When a Setting is updated, the following checks take place:

- If set, `disable-inactive-user-after` must be zero or a positive duration and can't be less than `auth-user-session-ttl-minutes` (e.g. `240h`).
- If set, `delete-inactive-user-after` must be zero or a positive duration and can't be less than `336h` or `auth-user-session-ttl-minutes`, whichever is greater (e.g. `336h`).
- If set, `user-last-login-default` must be a date time according to RFC3339 (e.g. `2023-11-29T00:00:00Z`).
- If set, `user-retention-cron` must be a valid standard cron expression (e.g. `0 0 * * 1`).

### Forbidden - Update

- If `agent-tls-mode` has `default` or `value` updated from `system-store` to `strict`, then all non-local clusters must
  have a status condition `AgentTlsStrictCheck` set to `True`, unless the new setting has an overriding
  annotation `cattle.io/force=true`.
