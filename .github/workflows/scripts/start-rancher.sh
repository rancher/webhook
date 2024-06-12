#!/bin/bash

flip() {
    echo $1
    exit 1
}

kubectl get ns | grep -s cattle && flip 'rancher already installed?'

set -exu

set +e
helm repo add cert-manager https://charts.jetstack.io
helm repo add rancher-latest https://releases.rancher.com/server-charts/latest
helm repo add jetstack https://charts.jetstack.io
set -e

helm repo update

helm upgrade --install cert-manager --namespace cert-manager cert-manager/cert-manager --set installCRDs=true --create-namespace --wait --timeout=10m

# kubectl get pods --namespace cert-manager
kubectl rollout status --namespace cert-manager deploy/cert-manager --timeout 1m

# Chart based

helm upgrade --install rancher "$CHART_PATH" --namespace cattle-system --set replicas=1 --set hostname=localhost --wait --timeout=10m --create-namespace --version "$VERSION" --set rancherImage=rancher/rancher --set rancherImageTag="$RANCHER_IMAGE_TAG"
