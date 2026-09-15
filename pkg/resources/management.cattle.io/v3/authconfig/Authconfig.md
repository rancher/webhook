
## Validation Checks

### Create and Update

When an LDAP (`openldap`, `freeipa`) or ActiveDirectory (`activedirectory`) authconfig is created or updated, the following checks take place:

- The field `servers` is required.
- If set, the following fields should have valid LDAP attribute names according to RFC4512
  - `userSearchAttribute`
  - `userLoginAttribute`
  - `userObjectClass`
  - `userNameAttribute`
  - `userMemberAttribute` (only for LDAP authconfigs)
  - `userEnabledAttribute`
  - `groupSearchAttribute`
  - `groupObjectClass`
  - `groupNameAttribute`
  - `groupDNAttribute`
  - `groupMemberUserAttribute`
  - `groupMemberMappingAttribute`
  - `userIDAttribute`
  - `groupIDAttribute`
- If set, the following fields should have a valid LDAP filter expression according to RFC4515
  - `userLoginFilter`
  - `userSearchFilter`
  - `groupSearchFilter`

When a SAML authconfig with LDAP search (`shibboleth`, `okta`) is created or updated, the following fields of the embedded `openLdapConfig` should have valid LDAP attribute names according to RFC4512 if set:

- `userIDAttribute`
- `groupIDAttribute`

These two fields are not immutable for SAML authconfigs. SAML principal IDs come from the assertion, and the LDAP attributes only have to match the values the identity provider sends in the UID and groups fields, which an admin may need to adjust at any time.

### Update

When an enabled LDAP or ActiveDirectory authconfig is updated and remains enabled, the following fields cannot be changed:

- `userIDAttribute`
- `groupIDAttribute`

Those providers build principal IDs from the attribute at login, so changing it would orphan every binding that references the old principal names. Disabling the provider with the default cleanup annotation removes its users, tokens, and bindings, so re-enabling with a different identifier attribute is a clean start. With the `user-locked` cleanup annotation, cleanup is skipped and the preserved users and bindings keep principal IDs that no longer resolve after the change.
