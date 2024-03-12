## Validation Checks

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
