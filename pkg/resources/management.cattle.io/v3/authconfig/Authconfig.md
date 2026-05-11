
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

### Update

When an enabled LDAP or ActiveDirectory authconfig is updated and remains enabled, the following fields cannot be changed:

- `userIDAttribute`
- `groupIDAttribute`

To change these fields, first disable the provider, apply the change, then re-enable it.
