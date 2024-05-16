#!/bin/bash

./scripts/package-for-ci

export KUBECONFIG=$HOME/.kube/config
export CATTLE_DEV_MODE=yes
export CATTLE_SERVER_URL="https://$(ip route get 8.8.8.8 | awk '{print $7}'):443"
export CATTLE_BOOTSTRAP_PASSWORD="admin"
export CATTLE_FEATURES="harvester=false"

export CLUSTER_NAME=webhook
export K3S_VERSION=v1.26.15-k3s1
docker pull rancher/k3s:$K3S_VERSION
./.github/workflows/scripts/setup-cluster.sh
./.github/workflows/scripts/start-rancher.sh



# Now bring in integration-test stuff

./.github/workflows/scripts/continue-testing.sh
