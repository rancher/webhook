## Validation Checks

### On Create

#### Creator ID Annotation

The annotation `field.cattle.io/creatorId` must be set to the Username of the User that initiated the request.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` cannot be set.

#### NO_PROXY value

Prevent the creation of new objects with an env var (under `spec.agentEnvVars`) with a name of `NO_PROXY` if its value contains one or more spaces. This ensures that the provided value adheres to
the format expected by Go, and helps to prevent subtle issues elsewhere when writing scripts which utilize `NO_PROXY`.  

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

The annotation `field.cattle.io/creatorId` cannot be changed, but it can be removed.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` cannot be set.

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

### cluster.spec.clusterAgentDeploymentCustomization.schedulingCustomization

The `SchedulingCustomization` subfield of the `DeploymentCustomization` field defines the properties of a Pod Disruption Budget and Priority Class which will be automatically deployed by Rancher for the cattle-cluster-agent.

The `schedulingCustomization.PriorityClass` field contains two attributes

+ `value`: This must be an integer value equal to or between negative 1 billion and 1 billion.
+ `preemptionPolicy`: This must be a string value which indicates the desired preemption behavior, its value can be either `PreemptLowerPriority` or `Never`. Any other value must be rejected.

The `schedulingCustomization.PodDisruptionBudget` field contains two attributes

+ `minAvailable`: This is a string value that indicates the minimum number of agent replicas that must be running at a given time.
+ `maxUnavailable`: This is a string value that indicates the maximum number of agent replicas that can be unavailable at a given time.

Both `minAvailable` and `maxUnavailable` must be a string which represents a non-negative whole number, or a whole number percentage greater than or equal to `0%` and less than or equal to `100%`. Only one of the two fields can have a non-zero or empty value at a given time. These fields use the following regex when assessing if a given percentage value is valid:
```regex
^([0-9]|[1-9][0-9]|100)%$
```

#### NO_PROXY value

Prevent the creation of new objects with an env var (under `spec.agentEnvVars`) with a name of `NO_PROXY` if its value contains one or more spaces. This ensures that the provided value adheres to
the format expected by Go, and helps to prevent subtle issues elsewhere when writing scripts which utilize `NO_PROXY`.  

The only exception to this check is if the existing cluster already has a `NO_PROXY` variable which includes spaces in its value. In this case, update operations are permitted. If `NO_PROXY` is later updated to value which does not contain spaces, this exception will no longer occur.

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

