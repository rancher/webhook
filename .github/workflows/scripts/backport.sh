#!/bin/sh

set -e

PULL_REQUEST=$1
TARGET_BRANCH=$2
CHERRY_PICK=$3
REPO=$4

if [ -z "$PULL_REQUEST" ] || [ -z "$TARGET_BRANCH" ] || [ -z "$CHERRY_PICK" ] || [ -z "$REPO" ]; then
	echo "Usage: $0 <PR number> <target branch> <true|false> <owner/repo>" 1>&2
	exit 1
fi

GITHUB_TRIGGERING_ACTOR=${GITHUB_TRIGGERING_ACTOR:-}

repo_name=$(echo "$REPO" | cut -d/ -f2)
repo_owner=$(echo "$REPO" | cut -d/ -f1)

target_slug=$(echo "$TARGET_BRANCH" | sed "s|/|-|")
branch_name="backport-$PULL_REQUEST-$target_slug-$$"

pr_link=https://github.com/$REPO/pull/$PULL_REQUEST
pr_number=$PULL_REQUEST

# Separate calls because otherwise it was creating trouble.. can probably be fixed
state=$(gh pr view "$pr_number" --json state --jq '.state')
old_title=$(gh pr view "$pr_number" --json title --jq '.title')
old_body=$(gh pr view "$pr_number" --json body --jq '.body')

if [ $state != "MERGED" ]; then
	echo "PR $pr_number ($pr_link) not yet merged, cannot backport" 1>&2
	exit 1
fi

git fetch origin "$TARGET_BRANCH:$branch_name"
git switch "$branch_name"

committed_something=""

if [ "$CHERRY_PICK" = "true" ]; then
	git fetch origin "pull/$pr_number/head:to-cherry-pick"
	commit=$(git rev-parse to-cherry-pick)
	if git cherry-pick --allow-empty "$commit"; then
		committed_something="true"
	else
		echo "Cherry-pick failed, skipping" 1>&2
		git cherry-pick --abort
	fi
fi

if [ -z "$committed_something" ]; then
	# Github won't allow us to create a PR without any changes so we're making an empty commit here
	git commit --allow-empty -m "Please amend this commit"
fi

git push -u origin "$branch_name"

generated_by=""
if [ -n "$GITHUB_TRIGGERING_ACTOR" ]; then
    generated_by=$(cat <<EOF
The workflow was triggered by @$GITHUB_TRIGGERING_ACTOR.
EOF
)
fi

title=$(echo "[$TARGET_BRANCH] $old_title")
body=$(cat <<EOF
**Backport**

Backport of $pr_link

You can make changes to this PR with the following command:

\`\`\`
git clone https://github.com/$REPO
cd $repo_name
git switch $branch_name
\`\`\`

$generated_by

---

$old_body
EOF
)

gh pr create \
  --title "$title" \
  --body "$body" \
  --repo "$REPO" \
  --head "$repo_owner:$branch_name" \
  --base "$TARGET_BRANCH" \
  --draft
