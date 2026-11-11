#!/bin/bash
# Prepares charts/rancher-webhook for an OCI release with cargueiro: sets the
# appVersion and image tag to the release tag, stamps the final chart version,
# checks it and packages it. Prints the path of the packaged chart on stdout.
#
# The chart version is <chart major>.0.<webhook patch>+up<webhook version>,
# with the chart major read from the "Chart Major Version" column of
# VERSION.md for the webhook minor of the tag.
#
# Usage: stamp-chart.sh <tag> <output dir>
#   e.g. stamp-chart.sh v0.13.0-rc.1 dist/oci
#
# Requires cargueiro on PATH. Run from the repository root.
set -euo pipefail

TAG=${1:?usage: $0 <tag> <output dir>}
OUT_DIR=${2:?usage: $0 <tag> <output dir>}

if ! [[ "$TAG" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)(-[0-9A-Za-z.]+)?$ ]]; then
  echo "Error: tag $TAG must look like vX.Y.Z or vX.Y.Z-rc.N" >&2
  exit 1
fi
MINOR="v${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"
PATCH="${BASH_REMATCH[3]}"
APP_VERSION="${TAG#v}"

# | Webhook Branch | Webhook Minor version | Rancher Minor Version | Chart Major Version |
CHART_MAJOR=$(awk -F'|' -v minor="$MINOR" '{gsub(/ /, "", $3); gsub(/ /, "", $5)} $3 == minor {print $5}' VERSION.md)
if ! [[ "$CHART_MAJOR" =~ ^[0-9]+$ ]]; then
  echo "Error: no chart major for $MINOR in VERSION.md (got '$CHART_MAJOR')" >&2
  exit 1
fi
CHART_VERSION="${CHART_MAJOR}.0.${PATCH}+up${APP_VERSION}"

BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT
CHART_DIR="$BUILD_DIR/rancher-webhook"
cp -r charts/rancher-webhook "$CHART_DIR"

# stamp sets the version and adds missing images to helm.sh/images, but
# neither the appVersion nor the image tag, which are "latest" in the source.
sed -i \
  -e "s|^appVersion:.*|appVersion: ${APP_VERSION}|" \
  -e "s|image: rancher/rancher-webhook:latest|image: rancher/rancher-webhook:${TAG}|" \
  "$CHART_DIR/Chart.yaml"
sed -i -e "s|tag: latest|tag: ${TAG}|" "$CHART_DIR/values.yaml"

cargueiro stamp "$CHART_DIR" --version "$CHART_VERSION" >&2
cargueiro check chart "$CHART_DIR" >&2
cargueiro package "$CHART_DIR" --output-dir "$OUT_DIR"
