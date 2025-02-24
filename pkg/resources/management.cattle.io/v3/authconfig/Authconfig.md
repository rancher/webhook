
## Validation Checks

### Create and Update

When an LDAP (`openldap`, `freeipa`) or AD (`activedirectory`) authconfig is are created or updated, the following common checks take place:

- The field `servers` is required.
- If the field `tls` is set to true, the field `certificate` is required.
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
- If set, the following fields should have a valid LDAP filter expression
  - `userLoginFilter`
  - `userSearchFilter`
  - `groupSearchFilter`
