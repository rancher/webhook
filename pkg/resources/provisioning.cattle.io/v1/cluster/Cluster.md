## Validation Checks

### cluster.spec.clusterAgentDeploymentCustomization and cluster.spec.fleetAgentDeploymentCustomization

`Key rule`: The keys are being validated to match the kubernetes requirement. 63 Characteres maximum, Regex:
`([A-Za-z0-9][-A-Za-z0-9_.]*)?[A-Za-z0-9]` it also accepts a "/"

`appendTolerations`:  is being validated with the  `{Key Rule}`

`affinity.nodeAffinity`:  The nodeSelectorTerms  (`requiredDuringSchedulingIgnoredDuringExecution` and 
`preferredDuringSchedulingIgnoredDuringExecution.preference`) are being validated with the `{Key Rule}`. 

`affinity.podAffinity and affinity.podAntiAffinity`:  The labelSelectors 
(`requiredDuringSchedulingIgnoredDuringExecution` and `preferredDuringSchedulingIgnoredDuringExecution.podAffinityTerm``)
are being validated using the k8s apimachinery rules. The `{Key Rule}` is part of it. 