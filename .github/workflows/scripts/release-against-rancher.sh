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

bump_patch() {
    version=$1
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)
    patch=$(echo "$version" | cut -d. -f3)
    new_patch=$((patch + 1))
    echo "${major}.${minor}.${new_patch}"
}

validate_version_format() {
    version=$1
    if ! echo "$version" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'; then
        echo "Error: Version $version must be in the format v<major>.<minor>.<patch> or v<major>.<minor>.<patch>-rc.<number>"
        exit 1
    fi
}

if [ -z "$RANCHER_DIR" ] || [ -z "$NEW_WEBHOOK_VERSION" ]; then
    usage
    exit 1
fi

validate_version_format "$NEW_WEBHOOK_VERSION"

# Remove the prefix v because the chart version doesn't contain it
NEW_WEBHOOK_VERSION_SHORT=$(echo "$NEW_WEBHOOK_VERSION" | sed 's|^v||')  # e.g. 0.5.2-rc.3

set -ue

pushd "${RANCHER_DIR}" > /dev/null

# Get the webhook version (eg: 0.5.0-rc.12)
if ! PREV_WEBHOOK_VERSION_SHORT=$(yq -r '.webhookVersion' ./build.yaml | sed 's|.*+up||'); then
    echo "Unable to get webhook version from ./build.yaml. The content of the file is:"
    cat ./build.yaml
    exit 1
fi

if [ "$PREV_WEBHOOK_VERSION_SHORT" = "$NEW_WEBHOOK_VERSION_SHORT" ]; then
    echo "Previous and new webhook version are the same: $NEW_WEBHOOK_VERSION, but must be different"
    exit 1
fi

if echo "$PREV_WEBHOOK_VERSION_SHORT" | grep -q '\-rc'; then
    is_prev_rc=true
else
    is_prev_rc=false
fi

# Get the chart version (eg: 104.0.0)
if ! PREV_CHART_VERSION=$(yq -r '.webhookVersion' ./build.yaml | cut -d+ -f1); then
    echo "Unable to get chart version from ./build.yaml. The content of the file is:"
    cat ./build.yaml
    exit 1
fi

if [ "$is_prev_rc" = "false" ]; then
    NEW_CHART_VERSION=$(bump_patch "$PREV_CHART_VERSION")
else
    NEW_CHART_VERSION=$PREV_CHART_VERSION
fi

yq --inplace ".webhookVersion = \"${NEW_CHART_VERSION}+up${NEW_WEBHOOK_VERSION_SHORT}\"" ./build.yaml

go generate ./...

git add .
git commit -m "Bump webhook to ${NEW_CHART_VERSION}+up${NEW_WEBHOOK_VERSION_SHORT}"

popd > /dev/null
