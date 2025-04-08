#!/bin/sh
#
# Automatically generates a message for a new release of webhook with some useful
# links and embedded release notes.
#
# Usage:
#   ./release-message.sh <prev webhook release> <new webhook release>
#
# Example:
# ./release-message.sh "v0.5.2-rc.3" "v0.5.2-rc.4"

PREV_WEBHOOK_VERSION=$1   # e.g. v0.5.2-rc.3
NEW_WEBHOOK_VERSION=$2    # e.g. v0.5.2-rc.4
GITHUB_TRIGGERING_ACTOR=${GITHUB_TRIGGERING_ACTOR:-}

usage() {
    cat <<EOF
Usage:
  $0 <prev webhook release> <new webhook release>
EOF
}

if [ -z "$PREV_WEBHOOK_VERSION" ] || [ -z "$NEW_WEBHOOK_VERSION" ]; then
    usage
    exit 1
fi

set -ue

# XXX: That's wasteful but doing it by caching the response in a var was giving
# me unicode error.
url=$(gh release view --repo rancher/webhook --json url "${NEW_WEBHOOK_VERSION}" --jq '.url')
body=$(gh release view --repo rancher/webhook --json body "${NEW_WEBHOOK_VERSION}" --jq '.body')

generated_by=""
if [ -n "$GITHUB_TRIGGERING_ACTOR" ]; then
    generated_by=$(cat <<EOF
# About this PR

The workflow was triggered by $GITHUB_TRIGGERING_ACTOR.
EOF
)
fi

cat <<EOF
# Release note for [${NEW_WEBHOOK_VERSION}]($url)

$body

# Useful links

- Commit comparison: https://github.com/rancher/webhook/compare/${PREV_WEBHOOK_VERSION}...${NEW_WEBHOOK_VERSION}
- Release ${PREV_WEBHOOK_VERSION}: https://github.com/rancher/webhook/releases/tag/${PREV_WEBHOOK_VERSION}

$generated_by
EOF
