#!/bin/bash
#
# Bumps Webhook version in a locally checked out rancher/rancher repository
#
# Usage:
#   ./release-against-rancher.sh <path to rancher repo> <new webhook release>
#
# Example:
# ./release-against-charts.sh "${GITHUB_WORKSPACE}" "v0.5.0-rc.14"

RANCHER_DIR=$1
NEW_WEBHOOK_VERSION=$2   # e.g. v0.5.2-rc.3

usage() {
    cat <<EOF
Usage:
  $0 <path to rancher repo> <new webhook release>
EOF
}

if [ -z "$RANCHER_DIR" ] || [ -z "$NEW_WEBHOOK_VERSION" ]; then
    usage
    exit 1
fi

# Remove the prefix v because the chart version doesn't contain it
NEW_WEBHOOK_VERSION_SHORT=$(echo "$NEW_WEBHOOK_VERSION" | sed 's|^v||')  # e.g. 0.5.2-rc.3

set -ue

pushd "${RANCHER_DIR}" > /dev/null

# Validate the given webhook version (eg: 0.5.0-rc.13)
if grep -q "${NEW_WEBHOOK_VERSION_SHORT}" ./build.yaml; then
    echo "build.yaml already at version ${NEW_WEBHOOK_VERSION}"
    exit 1
fi

# Get the chart version (eg: 104.0.0)
if ! PREV_CHART_VERSION=$(yq -r '.webhookVersion' ./build.yaml | cut -d+ -f1); then
    echo "Unable to get chart version from ./build.yaml. The content of the file is:"
    cat ./build.yaml
    exit 1
fi
NEW_CHART_VERSION=$PREV_CHART_VERSION

yq --inplace ".webhookVersion = \"${NEW_CHART_VERSION}+up${NEW_WEBHOOK_VERSION_SHORT}\"" ./build.yaml

# Downloads dapper
make .dapper

# DAPPER_MODE=bind will make sure we output everything that changed
DAPPER_MODE=bind ./.dapper go generate ./... || true
DAPPER_MODE=bind ./.dapper rm -rf go

git add .
git commit -m "Bump webhook to ${NEW_CHART_VERSION}+up${NEW_WEBHOOK_VERSION_SHORT}"

popd > /dev/null
