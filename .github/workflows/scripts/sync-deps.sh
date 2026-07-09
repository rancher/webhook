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

# Build a small, isolated helper that compares two semver strings using
# golang.org/x/mod/semver. It lives in its own temp module so it never
# touches the webhook go.mod/go.sum.
#
# Why golang.org/x/mod/semver instead of `sort -V`:
#   `sort -V` does not implement the semver precedence spec. It ranks a
#   prerelease ABOVE its own final release, e.g. it treats
#   `v0.9.0-rc.3` > `v0.9.0` because the `-rc.3` suffix is just extra
#   characters to it. Semver says the opposite: a prerelease is LOWER than
#   the release it precedes. That difference bites this exact workflow every
#   time a dep graduates rc -> final: rancher moves to `v0.9.0` while webhook
#   is still on `v0.9.0-rc.3`, and a `sort -V` check would wrongly decide
#   webhook is already ahead and skip the (correct) forward sync, leaving
#   webhook pinned to a prerelease after the release shipped.
#   golang.org/x/mod/semver follows the spec and also orders `-rc.N`
#   prereleases and `v0.0.0-<timestamp>-<hash>` pseudo-versions correctly.
SEMVER_BIN=""
build_semver_helper() {
  tmp=$(mktemp -d)
  # Match the go directive to the toolchain actually running this script so the
  # helper module never demands a newer/older Go than CI provides.
  gover=$(go env GOVERSION)
  gover=${gover#go}
  cat > "$tmp/go.mod" <<EOF
module semvercmp

go ${gover}

require golang.org/x/mod v0.21.0
EOF
  cat > "$tmp/main.go" <<'EOF'
package main

import (
	"fmt"
	"os"

	"golang.org/x/mod/semver"
)

// Prints "invalid" if either argument is not a valid semver string, otherwise
// prints -1, 0, or 1 for semver.Compare(a, b).
func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: semvercmp <a> <b>")
		os.Exit(2)
	}
	a, b := os.Args[1], os.Args[2]
	if !semver.IsValid(a) || !semver.IsValid(b) {
		fmt.Println("invalid")
		return
	}
	fmt.Println(semver.Compare(a, b))
}
EOF
  (
    cd "$tmp"
    GOFLAGS= go mod tidy
    GOFLAGS= go build -o semvercmp .
  )
  SEMVER_BIN="$tmp/semvercmp"
}

# semver_compare <a> <b> -> prints -1 / 0 / 1 (a<b / a==b / a>b)
semver_compare() {
  "$SEMVER_BIN" "$1" "$2"
}

# maybe_update_dep <module> <webhook_version> <rancher_version>
# Only updates when rancher's version is strictly newer than webhook's, so the
# sync never recommends a downgrade. Equal versions are a no-op; cases where
# webhook is already ahead are logged (but produce no change / no PR).
maybe_update_dep() {
  module=$1
  webhook_version=$2
  rancher_version=$3

  if [ "$rancher_version" = "$webhook_version" ]; then
    return
  fi

  cmp=$(semver_compare "$rancher_version" "$webhook_version")
  case "$cmp" in
    1)
      # rancher is strictly newer -> sync forward
      update_dep "$module" "$webhook_version" "$rancher_version"
      ;;
    -1|0)
      # rancher is older (or semver-equal despite different strings): never downgrade
      echo "Skipping $module: webhook version ($webhook_version) is newer than rancher ($rancher_version); not downgrading"
      ;;
    *)
      # One of the versions is not valid semver (e.g. an unresolved commit hash).
      # Can't compare safely, so preserve the original behavior and sync to rancher.
      echo "Warning: cannot semver-compare $module (rancher=$rancher_version, webhook=$webhook_version); syncing to rancher"
      update_dep "$module" "$webhook_version" "$rancher_version"
      ;;
  esac
}

update_dep() {
  module=$1
  old_version=$2
  new_version=$3

  echo "Version mismatch for $module (rancher=$new_version, webhook=$old_version) detected"
  go mod edit -require="$module@$new_version"
  printf '**%s**\n`%s` => `%s`\n' "$module" "$old_version" "$new_version" >> "$CHANGES_FILE"
}

build_semver_helper

rancher_deps=$(cd "$RANCHER_REPO_DIR" && go mod graph)
webhook_deps=$(go mod graph)

rancher_ref=$(cd "$RANCHER_REPO_DIR" && git rev-parse HEAD)
if ! rancher_pkg_apis_version=$(go mod download -json "github.com/rancher/rancher/pkg/apis@$rancher_ref" | jq -r '.Version'); then
  echo "Unable to get version of $PKG_APIS"
  exit 1
fi
webhook_pkg_apis_version=$(echo "$webhook_deps" | grep "^$PKG_APIS@\w*\S" | head -n 1 | cut -d' ' -f1 | cut -d@ -f2)

maybe_update_dep "$PKG_APIS" "$webhook_pkg_apis_version" "$rancher_pkg_apis_version"

for dep in $DEPS_TO_SYNC; do
  if ! rancher_version=$(echo "$rancher_deps" | grep "^$dep@\w*\S"); then
    continue
  fi

  if ! webhook_version=$(echo "$webhook_deps" | grep "^$dep@\w*\S"); then
    continue
  fi

  rancher_version=$(echo "$rancher_version" | head -n 1 | cut -d' ' -f1 | cut -d@ -f2)
  webhook_version=$(echo "$webhook_version" | head -n 1 | cut -d' ' -f1 | cut -d@ -f2)

  maybe_update_dep "$dep" "$webhook_version" "$rancher_version"
done

echo "Running go mod tidy"
go mod tidy
