## Validation Checks

### On Create

#### Data Directories

Prevent the creation of new objects with an invalid data directory. An invalid data directory is defined as the
following:
- Is not an absolute path (i.e. does not start with `/`)
- Attempts to include environment variables (e.g. `$VARIABLE` or `${VARIABLE}`)
- Attempts to include shell expressions (e.g. `$(command)` or `` `command` ``)
- Contains whitespace, non-printing characters (e.g. a newline or a zero-width space), or a backslash
- Is not clean (e.g. contains `.` or `..`)
- Equal to another data directory
- Attempts to nest another data directory

#### Registry Config Keys

Prevent the creation of new objects with an invalid key in `spec.registries.configs`. A registry config key must be a
registry host in the form of `host` or `host:port`, optionally followed by a path (e.g. `registry.example.com/team`).
The host is a host name, an IPv4 address, or an IPv6 address in square brackets, and the port is between `1` and
`65535`. A path has non-empty segments of letters, digits, `.`, `_`, and `-`. A key must not be empty, contain
whitespace or control characters (e.g. a newline), contain `..`, or start with `/`.

### On Update

#### Data Directories

Prevent updating objects with an invalid data directory. An invalid data directory is defined as the
following:
- Is not an absolute path (i.e. does not start with `/`)
- Attempts to include environment variables (e.g. `$VARIABLE` or `${VARIABLE}`)
- Attempts to include shell expressions (e.g. `$(command)` or `` `command` ``)
- Contains whitespace, non-printing characters (e.g. a newline or a zero-width space), or a backslash
- Is not clean (e.g. contains `.` or `..`)
- Equal to another data directory
- Attempts to nest another data directory

#### Registry Config Keys

Prevent adding an invalid key to `spec.registries.configs`. The rules are the same as on create. An existing key is not
validated, so existing objects can still be updated.
