#!/bin/sh
#
# Bumps Webhook version in a locally checked out rancher/charts repository
#
# Usage:
#   ./release-against-charts.sh <path to charts repo> <prev webhook release> <new webhook release>
#
# Example:
# ./release-against-charts.sh "${GITHUB_WORKSPACE}" "v0.5.0-rc.13" "v0.5.0-rc.14"

CHARTS_DIR=$1
PREV_WEBHOOK_VERSION=$2   # e.g. v0.5.2-rc.3
NEW_WEBHOOK_VERSION=$3    # e.g. v0.5.2-rc.4

usage() {
    cat <<EOF
Usage:
  $0 <path to charts repo> <prev webhook release> <new webhook release>
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

if [ -z "$CHARTS_DIR" ] || [ -z "$PREV_WEBHOOK_VERSION" ] || [ -z "$NEW_WEBHOOK_VERSION" ]; then
    usage
    exit 1
fi

validate_version_format "$PREV_WEBHOOK_VERSION"
validate_version_format "$NEW_WEBHOOK_VERSION"

if echo "$PREV_WEBHOOK_VERSION" | grep -q '\-rc'; then
    is_prev_rc=true
else
    is_prev_rc=false
fi

if [ "$PREV_WEBHOOK_VERSION" = "$NEW_WEBHOOK_VERSION" ]; then
    echo "Previous and new webhook version are the same: $NEW_WEBHOOK_VERSION, but must be different"
    exit 1
fi

# Remove the prefix v because the chart version doesn't contain it
PREV_WEBHOOK_VERSION_SHORT=$(echo "$PREV_WEBHOOK_VERSION" | sed 's|^v||')  # e.g. 0.5.2-rc.3
NEW_WEBHOOK_VERSION_SHORT=$(echo "$NEW_WEBHOOK_VERSION" | sed 's|^v||')  # e.g. 0.5.2-rc.4

set -ue

cd "${CHARTS_DIR}"

# Validate the given webhook version (eg: 0.5.0-rc.13)
if ! grep -q "${PREV_WEBHOOK_VERSION_SHORT}" ./packages/rancher-webhook/package.yaml; then
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

if [ "$is_prev_rc" = "false" ]; then
    NEW_CHART_VERSION=$(bump_patch "$PREV_CHART_VERSION")
else
    NEW_CHART_VERSION=$PREV_CHART_VERSION
fi

sed -i "s/${PREV_WEBHOOK_VERSION_SHORT}/${NEW_WEBHOOK_VERSION_SHORT}/g" ./packages/rancher-webhook/package.yaml
sed -i "s/${PREV_CHART_VERSION}/${NEW_CHART_VERSION}/g" ./packages/rancher-webhook/package.yaml

git add packages/rancher-webhook
git commit -m "Bump rancher-webhook to $NEW_WEBHOOK_VERSION"

PACKAGE=rancher-webhook make charts
git add ./assets/rancher-webhook ./charts/rancher-webhook index.yaml
git commit -m "make charts"

# Prepends to list
yq --inplace ".rancher-webhook = [\"${NEW_CHART_VERSION}+up${NEW_WEBHOOK_VERSION_SHORT}\"] + .rancher-webhook" release.yaml

git add release.yaml
git commit -m "Add rancher-webhook ${NEW_CHART_VERSION}+up${NEW_WEBHOOK_VERSION_SHORT} to release.yaml"
