#!/bin/sh
#
# 

set -e

RANCHER_REPO_DIR=$1
# File to write the changes to
CHANGES_FILE=${2:-/dev/null}

PKG_APIS="github.com/rancher/rancher/pkg/apis"
DEPS_TO_SYNC="
  github.com/rancher/dynamiclistener
  github.com/rancher/lasso
  github.com/rancher/wrangler
  github.com/rancher/wrangler/v2
  github.com/rancher/wrangler/v3
"

if [ -z "$RANCHER_REPO_DIR" ]; then
  usage
  exit 1
fi

usage() {
  echo "$0 <path to rancher repository> [<path to write dependency changes to>]"
}

update_dep() {
  module=$1
  old_version=$2
  new_version=$3

  echo "Version mismatch for $module (rancher=$new_version, webhook=$old_version) detected"
  go mod edit -require="$module@$new_version"
  printf '**%s**\n`%s` => `%s`\n' "$module" "$old_version" "$new_version" >> "$CHANGES_FILE"
}

rancher_deps=$(cd "$RANCHER_REPO_DIR" && go mod graph)
webhook_deps=$(go mod graph)

rancher_ref=$(cd "$RANCHER_REPO_DIR" && git rev-parse HEAD)
if ! rancher_pkg_apis_version=$(go mod download -json "github.com/rancher/rancher/pkg/apis@$rancher_ref" | jq -r '.Version'); then
  echo "Unable to get version of $PKG_APIS"
  exit 1
fi
webhook_pkg_apis_version=$(echo "$webhook_deps" | grep "^$PKG_APIS@\w*\S" | head -n 1 | cut -d' ' -f1 | cut -d@ -f2)

if [ "$rancher_pkg_apis_version" != "$webhook_pkg_apis_version" ]; then
  update_dep "$PKG_APIS" "$webhook_pkg_apis_version" "$rancher_pkg_apis_version"
fi

for dep in $DEPS_TO_SYNC; do
  if ! rancher_version=$(echo "$rancher_deps" | grep "^$dep@\w*\S"); then
    continue
  fi

  if ! webhook_version=$(echo "$webhook_deps" | grep "^$dep@\w*\S"); then
    continue
  fi

  rancher_version=$(echo "$rancher_version" | head -n 1 | cut -d' ' -f1 | cut -d@ -f2)
  webhook_version=$(echo "$webhook_version" | head -n 1 | cut -d' ' -f1 | cut -d@ -f2)
  if [ "$rancher_version" = "$webhook_version" ]; then
    continue
  fi

  update_dep "$dep" "$webhook_version" "$rancher_version"
done

echo "Running go mod tidy"
go mod tidy
