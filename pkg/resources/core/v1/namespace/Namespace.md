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

