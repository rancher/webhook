## Validation Checks

The webhook selects secrets with a special label and validates them on create and update.
The label is `cattle.io/project-scoped` with a value of `original`.

### On create

The webhook ensures the secret has an annotation `field.cattle.io/projectId` with a non-empty value. This value should
be the cluster ID.

### On update

On update, the webhook ensures that neither the annotation nor the special label `cattle.io/project-scoped` have been
changed.
