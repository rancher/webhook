#!/bin/bash

set -e

source ./scripts/version
set -x

echo $TAG

if [ -z "$CLUSTER_NAME" ]; then
    echo "CLUSTER_NAME must be specified when setting up a cluster"
    exit 1
fi

if [ -z "$K3S_VERSION" ]; then
  echo "K3S_VERSION must be specified when setting up a cluster, use $(k3d version list k3s) to find valid versions"
  exit 1
fi

# waits until all nodes are ready
wait_for_nodes(){
  timeout=120
  start_time=$(date +%s)
  echo "wait until all agents are ready"
  while :
  do
    current_time=$(date +%s)
    elapsed_time=$((current_time - start_time))
    if [ $elapsed_time -ge $timeout ]; then
        echo "Timeout reached, exiting..."
        exit 1
    fi

    readyNodes=1
    statusList=$(kubectl get nodes --no-headers | awk '{ print $2}')
    # shellcheck disable=SC2162
    while read status
    do
      current_time=$(date +%s)
      elapsed_time=$((current_time - start_time))
      if [ $elapsed_time -ge $timeout ]; then
          echo "Timeout reached, exiting..."
          exit 1
      fi
      if [ "$status" == "NotReady" ] || [ "$status" == "" ]
      then
        readyNodes=0
        break
      fi
    done <<< "$(echo -e  "$statusList")"
    # all nodes are ready; exit
    if [[ $readyNodes == 1 ]]
    then
      break
    fi
    sleep 1
  done
}

k3d registry create gha -p 42765
k3d cluster create $CLUSTER_NAME --servers 1 --agents 1 \
    --registry-use gha:42765 \
    --image "rancher/k3s:${K3S_VERSION}" --api-port 6550

wait_for_nodes

echo "k3d cluster $CLUSTER_NAME is ready"

kubectl cluster-info --context k3d-${CLUSTER_NAME}
kubectl config use-context k3d-${CLUSTER_NAME}
kubectl get nodes -o wide
kubectl get pods -A
