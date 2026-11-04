## Validation Checks

### On Create

#### Data Directories

Prevent the creation of new objects with an invalid data directory. An invalid data directory is defined as the
following:
- Is not an absolute path (i.e. does not start with `/`)
- Attempts to include environment variables (e.g. `$VARIABLE` or `${VARIABLE}`)
- Attempts to include shell expressions (e.g. `$(command)` or `` `command` ``)
- Is not clean (e.g. contains `.` or `..`)
- Equal to another data directory
- Attempts to nest another data directory

### On Update

#### Data Directories

Prevent updating objects with an invalid data directory. An invalid data directory is defined as the
following:
- Is not an absolute path (i.e. does not start with `/`)
- Attempts to include environment variables (e.g. `$VARIABLE` or `${VARIABLE}`)
- Attempts to include shell expressions (e.g. `$(command)` or `` `command` ``)
- Is not clean (e.g. contains `.` or `..`)
- Equal to another data directory
- Attempts to nest another data directory
