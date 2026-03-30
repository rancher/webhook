## Validation Checks

A secret cannot be deleted if its deletion request has an orphan policy,
and the secret has roles or role bindings dependent on it.

### Cloud Credential Validation

Secrets in the `cattle-cloud-credentials` namespace with a type prefix of `rke.cattle.io/cloud-credential-`
are validated against their corresponding DynamicSchema. The credential type is extracted from the secret
type suffix (e.g., `rke.cattle.io/cloud-credential-amazonec2` -> `amazonec2`), and the schema is looked up
as `<type>credentialconfig` (e.g., `amazonec2credentialconfig`).

Validation checks:
- All required fields defined in the DynamicSchema are present and non-empty.
- Field values conform to MinLength and MaxLength constraints.
- Field values match allowed Options (enum values) if defined.
- Extra fields not in the schema are allowed.
- Type/format validation beyond these checks is not currently enforced by this webhook.

Special cases:
- Generic credentials require the `generic-cloud-credentials` feature flag when no DynamicSchema exists.
- When that feature is enabled, schema-less credential types must use the `x-` prefix, while the backing Secret type `generic` is also allowed.
- DELETE operations check if the credential is referenced by provisioning clusters, machine pools, or ETCD S3 config.
  If the credential is in use, deletion is denied unless `GracePeriodSeconds=0` (force-delete) is set.

## Mutation Checks

### On create

For all secrets of type `provisioning.cattle.io/cloud-credential`, 
places a `field.cattle.io/creatorId` annotation with the name of the user as the value.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` does not get set.

For secrets stored in the `cattle-local-user-passwords` namespace containing local users passwords:
- Verifies the password has the minimum required length.
- Verifies the password is not the same as the username.
- Encrypts the password using pbkdf2.

### On delete

Checks if there are any RoleBindings owned by this secret which provide access to a role granting access to this secret.
If yes, the webhook redacts the role, so that it only grants a deletion permission.