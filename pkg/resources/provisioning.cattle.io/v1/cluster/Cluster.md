## Validation Checks

### On Create

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

#### Data Directories

On update, prevent new env vars with this name from being added but allow them to be removed. Rancher will perform 
a one-time migration to move the system-agent data dir definition to the top level field from the `AgentEnvVars` 
section. A secondary validator will ensure that the effective data directory for the `system-agent` is not different 
from the one chosen during cluster creation. Additionally, the changing of a data directory for the `system-agent`, 
kubernetes distro (RKE2/K3s), and CAPR components is also prohibited.

### cluster.spec.clusterAgentDeploymentCustomization and cluster.spec.fleetAgentDeploymentCustomization

The `DeploymentCustomization` fields are of 3 types:
- `appendTolerations`: adds tolerations to the appropriate deployment (cluster-agent/fleet-agent)
- `affinity`: adds various affinities to the deployments, which include the following
  - `nodeAffinity`: where to schedule the workload
  - `podAffinitity` and `podAntiAffinity`: pods to avoid or prefer when scheduling the workload

A `Toleration` is matched to a regex which is provided by upstream [apimachinery here](https://github.com/kubernetes/apimachinery/blob/02a41040d88da08de6765573ae2b1a51f424e1ca/pkg/apis/meta/v1/validation/validation.go#L96) but it boils down to this regex on the label:
```regex
([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]
```

For the `Affinity` based rules, the `podAffinity`/`podAntiAffinity` are validated via label selectors via [this apimachinery function](https://github.com/kubernetes/apimachinery/blob/02a41040d88da08de6765573ae2b1a51f424e1ca/pkg/apis/meta/v1/validation/validation.go#L56) whereas the `nodeAffinity` `nodeSelectorTerms` are validated via the same `Toleration` function.

## Mutation Checks

### On Update

#### Dynamic Schema Drop

Check for the presence of the `provisioning.cattle.io/allow-dynamic-schema-drop` annotation. If the value is `"true"`,
perform no mutations. If the value is not present or not `"true"`, compare the value of the `dynamicSchemaSpec` field
for each `machinePool`, to its' previous value. If the values are not identical, revert the value for the
`dynamicSchemaSpec` for the specific `machinePool`, but do not reject the request.

