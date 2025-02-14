
## Mutation Checks

#### Feature: version management on imported RKE2/K3s cluster 

- When a cluster is created or updated, add the `rancher.io/imported-cluster-version-management: system-default` annotation if the annotation is missing or its value is an empty string.


## Validation Checks

### Annotations validation

When a cluster is created and `field.cattle.io/creator-principal-name` annotation is set then `field.cattle.io/creatorId` annotation must be set as well. The value of `field.cattle.io/creator-principal-name` should match the creator's user principal id.

When a cluster is updated `field.cattle.io/creator-principal-name` and `field.cattle.io/creatorId` annotations must stay the same or removed.

If `field.cattle.io/no-creator-rbac` annotation is set, `field.cattle.io/creatorId` cannot be set.


#### Feature: version management on imported RKE2/K3s cluster

 - When a cluster is created or updated, the `rancher.io/imported-cluster-version-management` annotation must be set with a valid value (true, false, or system-default). 
 - If the cluster represents other types of clusters and the annotation is present, the webhook will permit the request with a warning that the annotation is intended for imported RKE2/k3s clusters and will not take effect on this cluster.
 - If version management is determined to be disabled, and the `.spec.rke2Config` or `.spec.k3sConfig` field exists in the new cluster object with a value different from the old one, the webhook will permit the update with a warning indicating that these changes will not take effect until version management is enabled for the cluster.
 - If version management is determined to be disabled, and the `.spec.rke2Config` or `.spec.k3sConfig` field is missing, the webhook will permit the request to allow users to remove the unused fields via API or Terraform.
