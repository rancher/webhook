#!/bin/bash

set -eu

REPO_URL=https://github.com/rancher/k3d
K3D_URL=https://raw.githubusercontent.com/k3d-io/k3d/main/install.sh

install_k3d(){
  if [ -z "${K3D_VERSION:-}" -o "${K3D_VERSION:-}" = "latest" ] ; then
    K3D_VERSION=$(curl -Ls -o /dev/null -w %{url_effective} "${REPO_URL}/releases/latest" | grep -oE "[^/]+$")
  fi
  echo -e "Downloading k3d@${K3D_VERSION} from ${K3D_URL}"
  curl --silent --fail ${K3D_URL} | TAG=${K3D_VERSION} bash
}

install_k3d

k3d version
