## Mutation Checks

### On Update

#### Dynamic Schema Drop

Check for the presence of the `provisioning.cattle.io/allow-dynamic-schema-drop` annotation. If the value is `"true"`, 
perform no mutations. If the value is not present or not `"true"`, compare the value of the `dynamicSchemaSpec` field 
for each `machinePool`, to its' previous value. If the values are not identical, revert the value for the 
`dynamicSchemaSpec` for the specific `machinePool`, but do not reject the request.
