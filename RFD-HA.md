# RFD: Enable High Availability for rancher-webhook

## Metadata

* Authors: *Chad Roberts (chad.roberts@suse.com)*
* Relevant links:
    * PD&O / PRD / requirement document: N/A
    * SURE escalations, GitHub issues: https://jira.suse.com/browse/SURE-8650 https://github.com/rancher/rancher/issues/52202
    * Security Assessment: N/A (RFD will not affect authentication or authorization mechanisms)
    * UI/UX Changes: Yes, UI/UX changes are likely.

## Summary

This document proposes adding support for running the `rancher-webhook` in a multi-replica, highly available configuration. This will improve the reliability and availability of the webhook, which is a critical component for both the local Rancher cluster and downstream Kubernetes clusters.

## Background

The `rancher-webhook` is a Kubernetes admission controller that performs both validation and mutation of resources. It is deployed in the local Rancher cluster and is also automatically deployed to all downstream clusters managed by Rancher. The webhook is responsible for enforcing various policies and for mutating resources as they are created and updated. For example, it ensures that `GlobalRole` objects have valid rules and injects creator information into `Secret` objects.

Given its critical role, the availability of the `rancher-webhook` is essential for the smooth operation of the Rancher management plane and the downstream clusters.

## Problem Statement

Currently, the `rancher-webhook` Helm chart only supports deploying a single replica of the webhook pod. This creates a single point of failure. If the webhook pod crashes, is evicted, or the node it is running on fails, the webhook service will be unavailable. This can lead to a disruption of cluster operations, as requests to the Kubernetes API server that require validation or mutation by the webhook may be blocked or processed incorrectly, depending on the failure policy of the webhook configurations.

## Analysis of Existing HA Capabilities

`rancher-webhook` is already designed to support a highly available, multi-replica deployment. The key components that enable this are:

*   **Leader Election:** The webhook uses the standard Kubernetes leader election mechanism (`k8s.io/client-go/tools/leaderelection`) to elect a single leader among the running instances. The leader is responsible for managing the `ValidatingWebhookConfiguration` and `MutatingWebhookConfiguration` resources. This prevents race conditions and ensures that the webhook configurations are always in a consistent state.

*   **Shared TLS Certificates:** The webhook uses `github.com/rancher/dynamiclistener` to manage its TLS certificates. The certificates and CA are stored in Kubernetes `Secrets` in the `cattle-system` namespace. This allows all webhook pods to mount and share the same TLS credentials, ensuring a consistent identity is presented to the Kubernetes API server.

These existing features mean that enabling HA for the webhook is a low-risk change that should not require significant architectural modifications to `rancher-webhook` itself.

## Proposed Changes

Given that `rancher-webhook` is able to run multiple pods already, this discussion is targeted at enumerating which options should be configurable
and which options (possibly all) will apply to upstream vs downstream clusters.

To enable HA for the `rancher-webhook`, we propose the following changes:

### 1. Helm Chart Modifications

The chart for rancher-webhook will be updated to include the following new values:

*   `replicaCount`: The number of replicas for the webhook `Deployment`. This will default to `1` to maintain the current behavior for existing installations.

*   `affinity`: A user-configurable `affinity` block for the webhook `Deployment`. We will provide a default `podAntiAffinity` rule to encourage the Kubernetes scheduler to place webhook pods on different nodes. This will improve availability in the event of a node failure.
If we do include podAntiAffinity, we need to decide what the default should be.

*   `resources`: A user-configurable `resources` block for the webhook `Deployment`. This allows users to set CPU and memory requests and limits for the webhook container. We should provide sensible defaults but allow users to tune these based on their cluster's load.
Additionally, we may want to provide guidance on appropriate values for different cluster sizes and uses.

* The webhook deployment chart will be updated to use these new values.

### 2. PodDisruptionBudget (PDB)

A `PodDisruptionBudget` (PDB) is a Kubernetes resource that limits the number of pods of a replicated application that are down simultaneously from voluntary disruptions. Voluntary disruptions include actions initiated by the user or administrator, such as deleting a deployment, upgrading a deployment's template, or draining a node for maintenance.

We propose creating a PDB for the `rancher-webhook` deployment. This is crucial for maintaining high availability because it prevents Kubernetes from evicting too many webhook pods at once during maintenance operations. For instance, if a cluster administrator drains a node where a webhook pod is running, the PDB ensures that the eviction only proceeds if enough other replicas are available to handle the traffic.

The PDB will initially be configured to allow one unavailable replica (`minAvailable: 1` or `maxUnavailable: 1`). This ensures that even during maintenance, the webhook service remains operational.

### 3. UI changes

To support HA configuration for downstream clusters, the UI needs to be updated to allow users to configure the following settings for the `rancher-webhook`. 
It is my belief (but still up for discussion) that these settings should be configurable on a **per-cluster basis**, allowing administrators to tune the webhook deployment according to the specific needs and size of each downstream cluster.

*   `replicaCount`: To control the number of webhook replicas.
*   `resources`: To configure CPU and memory requests and limits.
*   `affinity`: To override the default anti-affinity rules.
*   `PodDisruptionBudget`: To override the deafult PodDisruptionBudget (if we do, in fact, decide to create one).

## Impact

### Local Cluster

In the local Rancher cluster, running multiple replicas of the webhook will make it more resilient to pod and node failures. If one webhook pod becomes unavailable, the Kubernetes `Service` will automatically route traffic to the healthy pods, ensuring that the webhook service remains available.

### Downstream Clusters

The `rancher-webhook` is also deployed to downstream clusters. The same HA benefits will apply to these clusters. However, the configuration of the webhook in downstream clusters is managed by Rancher itself, not directly by the Helm chart.

We will expose configuration options to allow users to customize the webhook deployment for each downstream cluster individually. This ensures that larger clusters can have more replicas and resources, while smaller clusters can use fewer resources.

## Questions

1.  Should the default `replicaCount` be changed to `2` or `3` for new installations to promote a more resilient default configuration?
2.  What is the recommended `replicaCount` for different sizes of clusters? Should we provide any guidance on this?
3.  Should we provide guidance on memory/cpu requests and limits?  What should our defaults be (currently, they are unspecified in the webhook deployment)?
4.  Should we introduce a `PodDisruptionBudget` for the webhook deployment to prevent voluntary disruptions from taking down all replicas at once?

## Other possibly related issues that are being worked on

1. https://github.com/rancher/rancher-security/issues/1243 (rancher-webhook is bound to cluster admin).  One of the possible solutions here may involve changing how rancher-webhook is deployed.
I'm not sure if that change materially affects what this discussion, but it could affect the reslutant implementation.
2. https://github.com/rancher/rancher/issues/50631 (Rancher does not wait for Webhook readiness).  The work done for this issue may also affect how webhook is installed.
3. https://github.com/rancher/webhook/issues/963 (Add resource requests/limits to rancher webhook helm chart).  This issue would likely be completed as part of the proposed changes for tihs RFD.

## Alternatives

1. We could choose to not expose some of the possible deployment options, which would simplify both the development and use of this functionality, but would make it considerably less useful.
2. We could choose to not make downstream webhook configuration a per-cluster feature, but that would make the feature much less flexible.
3. We could choose to let the users configure Horizontal Pod Autoscaling on their rancher-webhook deployments, but that doesn't appear to be a best practice for things like webhook functionality. 