#!/bin/bash
#
# Bumps Webhook version in a locally checked out rancher/rancher repository
#
# Usage:
#   ./release-against-rancher.sh <path to rancher repo> <new webhook release> <bump_major>
#
# Example:
# ./release-against-rancher.sh "${GITHUB_WORKSPACE}" "v0.5.0-rc.14" false

RANCHER_DIR=$1
NEW_WEBHOOK_VERSION=$2   # e.g. v0.5.2-rc.3
BUMP_MAJOR=$3            # must be "true" or "false"

usage() {
    cat <<EOF
Usage:
  $0 <path to rancher repo> <new webhook release> <bump_major>

Arguments:
  <path to rancher repo>   Path to locally checked out rancher repo
  <new webhook release>    New Webhook version (e.g. v0.5.0-rc.14, v0.5.0, v0.6.0-rc.0)
  <bump_major>             Must be "true" if introducing a new Webhook minor version, "false" otherwise.
                           Example: v0.5.0 → v0.6.0-rc.0 requires bump_major=true.

Examples:
  RC to RC:       $0 ./rancher v0.5.0-rc.1 false
  RC to stable:   $0 ./rancher v0.5.0 false
  stable → RC:    $0 ./rancher v0.5.1-rc.0 false
  new minor RC:   $0 ./rancher v0.6.0-rc.0 true
EOF
}

# Bumps the patch version of a semver version string
# e.g. 1.2.3 -> 1.2.4
# e.g. 1.2.3-rc.4 -> 1.2.4
bump_patch() {
    version=$1
    major=$(echo "$version" | cut -d. -f1)
    minor=$(echo "$version" | cut -d. -f2)
    patch=$(echo "$version" | cut -d. -f3)
    new_patch=$((patch + 1))
    echo "${major}.${minor}.${new_patch}"
}

# Bumps the major version of a semver version string and resets minor and patch to 0
# e.g. 1.2.3 -> 2.0.0
# e.g. 1.2.3-rc.4 -> 2.0.0
bump_major() {
    version=$1
    major=$(echo "$version" | cut -d. -f1)
    # Increment major, reset minor/patch to 0
    new_major=$((major + 1))
    echo "${new_major}.0.0"
}

# Validates that the version is in the format v<major>.<minor>.<patch> or v<major>.<minor>.<patch>-rc.<number>
validate_version_format() {
    version=$1
    if ! echo "$version" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+(-rc\.[0-9]+)?$'; then
        echo "Error: Version $version must be in the format v<major>.<minor>.<patch> or v<major>.<minor>.<patch>-rc.<number>"
        exit 1
    fi
}

if [ -z "$RANCHER_DIR" ] || [ -z "$NEW_WEBHOOK_VERSION" ] || [ -z "$BUMP_MAJOR" ]; then
    usage
    exit 1
fi

if [ "$BUMP_MAJOR" != "true" ] && [ "$BUMP_MAJOR" != "false" ]; then
    echo "Error: bump_major must be 'true' or 'false', got '$BUMP_MAJOR'"
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

prev_minor=$(echo "$PREV_WEBHOOK_VERSION_SHORT" | cut -d. -f2)
new_minor=$(echo "$NEW_WEBHOOK_VERSION_SHORT" | cut -d. -f2)

is_new_minor=false
if [ "$new_minor" -gt "$prev_minor" ]; then
    is_new_minor=true
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

# Determine new chart version
if [ "$is_new_minor" = "true" ]; then
    if [ "$BUMP_MAJOR" != "true" ]; then
        echo "Error: Detected new minor bump ($PREV_WEBHOOK_VERSION_SHORT → $NEW_WEBHOOK_VERSION_SHORT), but bump_major flag was not set."
        exit 1
    fi
    NEW_CHART_VERSION=$(bump_major "$PREV_CHART_VERSION")
    echo "Bumping chart major: $PREV_CHART_VERSION → $NEW_CHART_VERSION"
    COMMIT_MSG="Bump webhook to ${NEW_CHART_VERSION}+up${NEW_WEBHOOK_VERSION_SHORT} (chart version major bump)"
elif [ "$is_prev_rc" = "false" ]; then
    NEW_CHART_VERSION=$(bump_patch "$PREV_CHART_VERSION")
    COMMIT_MSG="Bump webhook to ${NEW_CHART_VERSION}+up${NEW_WEBHOOK_VERSION_SHORT} (chart version patch bump)"
else
    NEW_CHART_VERSION=$PREV_CHART_VERSION
    COMMIT_MSG="Bump webhook to ${NEW_CHART_VERSION}+up${NEW_WEBHOOK_VERSION_SHORT} (no chart version bump)"
fi

yq --inplace ".webhookVersion = \"${NEW_CHART_VERSION}+up${NEW_WEBHOOK_VERSION_SHORT}\"" ./build.yaml

# Downloads dapper
make .dapper

# DAPPER_MODE=bind will make sure we output everything that changed
DAPPER_MODE=bind ./.dapper go generate ./... || true
DAPPER_MODE=bind ./.dapper rm -rf go .config

git add .
git commit -m "$COMMIT_MSG"

popd > /dev/null
