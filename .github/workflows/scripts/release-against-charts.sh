#!/bin/bash
#
# Bumps Webhook version in a locally checked out rancher/charts repository
#
# Usage:
#   ./release-against-charts.sh <path to charts repo> <prev webhook release> <new webhook release>
#
# Example:
# ./release-against-charts.sh "${GITHUB_WORKSPACE}" "0.5.0-rc.13" "0.5.0-rc.14"

CHARTS_DIR=$1
PREV_WEBHOOK_VERSION=$2   # e.g. 0.5.2-rc.3
NEW_WEBHOOK_VERSION=$3

usage() {
    cat <<EOF
Usage:
  $0 <path to charts repo> <prev webhook release> <new webhook release>
EOF
}

if [ -z "$CHARTS_DIR" ] || [ -z "$PREV_WEBHOOK_VERSION" ] || [ -z "$NEW_WEBHOOK_VERSION" ]; then
    usage
    exit 1
fi

set -ue

pushd "${CHARTS_DIR}" > /dev/null

# Validate the given webhook version (eg: 0.5.0-rc.13)
if ! grep -q "${PREV_WEBHOOK_VERSION}" ./packages/rancher-webhook/package.yaml; then
    echo "Previous Webhook version references do not exist in ./packages/rancher-webhook/. The content of the file is:"
    cat ./packages/rancher-webhook/package.yaml
    exit 1
fi

# Get the chart version (eg: 104.0.0)
if ! PREV_CHART_VERSION=$(yq '.version' ./packages/rancher-webhook/package.yaml); then
    echo "Unable to get chart version from ./packages/rancher-webhook/package.yaml. The content of the file is:"
    cat ./packages/rancher-webhook/package.yaml
    exit 1
fi
NEW_CHART_VERSION=$PREV_CHART_VERSION

sed -i "s/${PREV_WEBHOOK_VERSION}/${NEW_WEBHOOK_VERSION}/g" ./packages/rancher-webhook/package.yaml

git add packages/rancher-webhook
git commit -m "Bump rancher-webhook to v$NEW_WEBHOOK_VERSION"

PACKAGE=rancher-webhook make charts
git add ./assets/rancher-webhook ./charts/rancher-webhook
git commit -m "make charts"

CHART=rancher-webhook VERSION=${PREV_CHART_VERSION}+up${PREV_WEBHOOK_VERSION} make remove
git add ./assets/rancher-webhook ./charts/rancher-webhook ./index.yaml
git commit -m "make remove"

yq --inplace "del(.rancher-webhook.[] | select(. == \"${PREV_CHART_VERSION}+up${PREV_WEBHOOK_VERSION}\"))" release.yaml
# Prepends to list
yq --inplace ".rancher-webhook = [\"${NEW_CHART_VERSION}+up${NEW_WEBHOOK_VERSION}\"] + .rancher-webhook" release.yaml

git add release.yaml
git commit -m "Add rancher-webhook ${NEW_CHART_VERSION}+up${NEW_WEBHOOK_VERSION} to release.yaml"
 
popd > /dev/null
