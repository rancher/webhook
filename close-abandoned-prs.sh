#!/usr/bin/env bash
# close-abandoned-prs.sh
# Closes all open Renovate PRs whose title contains "- abandoned".
# Usage:
#   ./close-abandoned-prs.sh          # dry run (default)
#   ./close-abandoned-prs.sh --close  # actually close the PRs

set -euo pipefail

DRY_RUN=true
if [[ "${1:-}" == "--close" ]]; then
  DRY_RUN=false
fi

REPO="rancher/webhook"
COMMENT="Closing: this Renovate PR has been marked abandoned and is no longer relevant."

echo "Fetching abandoned Renovate PRs from ${REPO}..."

# Collect all open PRs with "abandoned" in the title (paginate up to 500)
ABANDONED=$(gh pr list \
  --repo "${REPO}" \
  --state open \
  --limit 500 \
  --json number,title,author \
  --jq '.[] | select(.title | ascii_downcase | contains("abandoned")) | "\(.number)\t\(.title)"')

if [[ -z "${ABANDONED}" ]]; then
  echo "No abandoned PRs found."
  exit 0
fi

COUNT=$(echo "${ABANDONED}" | wc -l | tr -d ' ')

if "${DRY_RUN}"; then
  echo ""
  echo "DRY RUN — ${COUNT} PR(s) would be closed (run with --close to close them):"
  echo ""
  echo "${ABANDONED}" | while IFS=$'\t' read -r number title; do
    echo "  #${number}  ${title}"
  done
else
  echo ""
  echo "Closing ${COUNT} abandoned PR(s)..."
  echo ""
  echo "${ABANDONED}" | while IFS=$'\t' read -r number title; do
    echo "  Closing #${number}: ${title}"
    gh pr close "${number}" \
      --repo "${REPO}" \
      --comment "${COMMENT}" \
      --delete-branch 2>/dev/null || \
    gh pr close "${number}" \
      --repo "${REPO}" \
      --comment "${COMMENT}"
  done
  echo ""
  echo "Done. ${COUNT} PR(s) closed."
fi
