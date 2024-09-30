## Validation Checks

### On Create

#### Creator ID Annotation

The annotation `field.cattle.io/creatorId` must be set to the Username of the User that initiated the request.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` cannot be set.

#### Data Directories

Prevent the creation of new objects with an env var (under `spec.agentEnvVars`) with a name of `CATTLE_AGENT_VAR_DIR`.
Prevent the creation of new objects with an invalid data directory. An invalid data directory is defined as the 
following:
- Is not an absolute path (i.e. does not start with `/`)
- Attempts to include environment variables (e.g. `$VARIABLE` or `${VARIABLE}`)
- Attempts to include shell expressions (e.g. `$(command)` or `` `command` ``)
- Equal to another data directory
- Attempts to nest another data directory

### On Update

#### Creator ID Annotation

The annotation `field.cattle.io/creatorId` is cannot be changed, but it can be removed.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` cannot be set.

#### Data Directories

On update, prevent new env vars with this name from being added but allow them to be removed. Rancher will perform 
a one-time migration to move the system-agent data dir definition to the top level field from the `AgentEnvVars` 
section. A secondary validator will ensure that the effective data directory for the `system-agent` is not different 
from the one chosen during cluster creation. Additionally, the changing of a data directory for the `system-agent`, 
kubernetes distro (RKE2/K3s), and CAPR components is also prohibited.

## Mutation Checks

### On Create

When a cluster is created `field.cattle.io/creatorId` is set to the Username from the request.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` does not get set.

### On Update

#### Dynamic Schema Drop

Check for the presence of the `provisioning.cattle.io/allow-dynamic-schema-drop` annotation. If the value is `"true"`,
perform no mutations. If the value is not present or not `"true"`, compare the value of the `dynamicSchemaSpec` field
for each `machinePool`, to its' previous value. If the values are not identical, revert the value for the
`dynamicSchemaSpec` for the specific `machinePool`, but do not reject the request.
