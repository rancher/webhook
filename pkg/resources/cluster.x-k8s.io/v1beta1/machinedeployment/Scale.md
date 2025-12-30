# cluster.x-k8s.io/v1beta1

## MachineDeployment

### Validation Checks

#### On Create and Update

When a scale operation is performed on a MachineDeployment, the webhook synchronizes the replica count between the MachineDeployment and its corresponding machine pool in the Rancher provisioning cluster if it exists.

**Synchronization Flow:**

1. **Early Exit** - Skip synchronization if:
   - Dry-run request is detected
   - MachineDeployment doesn't exist
   - Required labels are missing (`cluster.x-k8s.io/cluster-name` or `rke.cattle.io/rke-machine-pool-name`)

2. **Cluster Resolution:**
   - Extracts the CAPI cluster name from the `cluster.x-k8s.io/cluster-name` label
   - Extracts the Rancher machine pool name from the `rke.cattle.io/rke-machine-pool-name` label
   - Retrieves the CAPI Cluster object using the cluster name label
   - Finds the Rancher Provisioning Cluster by checking owner references on the CAPI Cluster

3. **Machine Pool Matching:**
   - Validates the provisioning Cluster has RKEConfig and MachinePools configured
   - Locates the matching machine pool by name in the provisioning Cluster's RKEConfig
   - If not found, skips synchronization (no error)

4. **Replica Synchronization:**
   - Compares the replica count from the scale request with the machine pool's quantity
   - If they differ, updates the machine pool's quantity to match the scale request
   - Uses exponential backoff retry for update operations

**Error Handling:**
- Missing MachineDeployment: Admits the scale operation (not an error)
- Missing labels: Skips synchronization silently
- Missing CAPI Cluster: Returns error
- Missing Provisioning Cluster: Returns error
- Missing RKEConfig/MachinePools: Skips synchronization silently
- Machine pool not found: Skips synchronization silently
- Update failures: Returns error with escalation flag
