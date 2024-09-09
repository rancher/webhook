## Validation Checks

### Create and Update

When settings are created or updated, the following common checks take place:

- If set, `disable-inactive-user-after` must be zero or a positive duration (e.g. `240h`).
- If set, `delete-inactive-user-after` must be zero or a positive duration and can't be less than `336h` (e.g. `336h`).
- If set, `user-last-login-default` must be a date time according to RFC3339 (e.g. `2023-11-29T00:00:00Z`).
- If set, `user-retention-cron` must be a valid standard cron expression (e.g. `0 0 * * 0`).
- The `auth-user-session-ttl-minutes` must be a positive integer and can't be greater than `disable-inactive-user-after` or `delete-inactive-user-after` if those values are set.

### Update

When settings are updated, the following additional checks take place:

- If `agent-tls-mode` has `default` or `value` updated from `system-store` to `strict`, then all non-local clusters must
  have a status condition `AgentTlsStrictCheck` set to `True`, unless the new setting has an overriding
  annotation `cattle.io/force=true`.
