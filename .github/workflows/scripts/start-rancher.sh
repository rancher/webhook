#!/bin/bash

flip() {
    echo $1
    exit 1
}

kubectl get ns | grep -s cattle && flip 'rancher already installed?'

set -exu

helm repo list | grep -q cert-manager || helm repo add cert-manager https://charts.jetstack.io
helm repo list | grep -q rancher-latest || helm repo add rancher-latest https://releases.rancher.com/server-charts/latest
helm repo list | grep -q jetstack || helm repo add jetstack https://charts.jetstack.io

helm repo update

helm upgrade --install cert-manager --namespace cert-manager cert-manager/cert-manager --set installCRDs=true --set "extraArgs[0]=--enable-certificate-owner-ref=true" --create-namespace --wait --timeout=10m
 
# kubectl get pods --namespace cert-manager
kubectl rollout status --namespace cert-manager deploy/cert-manager --timeout 1m

VERSION=2.7
helm upgrade --install rancher rancher-latest/rancher --namespace cattle-system --set hostname=localhost --wait --timeout=10m --create-namespace --version $VERSION --set bootstrapPassword="${CATTLE_BOOTSTRAP_PASSWORD:-admin}"
