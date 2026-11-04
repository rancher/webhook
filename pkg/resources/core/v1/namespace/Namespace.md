## Validation Checks

Note: The `kube-system` namespace, unlike other namespaces, has a `failPolicy` of `ignore` on update calls.

### Project annotation
Verifies that the annotation `field.cattle.io/projectId` value can only be updated by users with the `manage-namespaces` 
verb on the project specified in the annotation.

### PSA Label Validation

Validates that users who create or edit a PSA enforcement label on a namespace have the `updatepsa` verb on `projects` 
in `management.cattle.io/v3`. See the [upstream docs](https://kubernetes.io/docs/concepts/security/pod-security-admission/) 
for more information on the effect of these labels.

The following labels are considered relevant for PSA enforcement: 
- pod-security.kubernetes.io/enforce
- pod-security.kubernetes.io/enforce-version 
- pod-security.kubernetes.io/audit 
- pod-security.kubernetes.io/audit-version 
- pod-security.kubernetes.io/warn
- pod-security.kubernetes.io/warn-version

### Namespace resource limit validation

Validation ensures that the limits for cpu/memory must not be less than the requests for cpu/memory.

### Protected namespace deletion

On the Rancher management (local) cluster, the `local` and `fleet-local` namespaces may not be deleted, as removing
them corrupts the Rancher installation.

This check is only registered when the webhook runs with multi-cluster management enabled. On downstream clusters
namespaces with those names belong to the user and can be deleted normally.
