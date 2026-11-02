#!/usr/bin/env bash
#
# Open the tap's bump PR for a rendered formula, or find the one already open.
# The release workflow's tap job runs this after bump.sh; it is safe to rerun
# at any point: an existing remote bump branch is reused rather than
# recreated, a commit is made only when the rendered formula differs from
# the branch's, an open PR for the branch is found before one is created, and
# nothing is ever force-pushed (a reviewer's commits on the branch stay).
#
#   tap-pr.sh FORMULA TAG
#
# FORMULA is the rendered formula (bump.sh -o), TAG its release (vX.Y.Z).
# Environment:
#   TAP          the tap repository, owner/name (default waffuruai/homebrew-tap)
#   TAP_TOKEN    a token with Contents and Pull requests write on TAP; unset
#                or empty, the script warns and exits 0 (the release is out
#                either way; the formula is the workflow's artifact)
#   TAP_URL      where to clone TAP from (default https://github.com/$TAP; the
#                test points it at a local bare repository)
#   SOURCE_REPO  the repository the release is on, for the PR body (default
#                $GITHUB_REPOSITORY, else waffuruai/pantry)
#
# The token reaches git only through gh's credential helper, configured in
# the environment: nothing is written to disk and nothing goes in a URL.

set -euo pipefail

[ $# -eq 2 ] || { echo "usage: $0 FORMULA TAG" >&2; exit 2; }
formula="$1" tag="$2"
[ -f "$formula" ] || { echo "tap-pr: no formula at $formula" >&2; exit 2; }
case "$tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "tap-pr: TAG must be vX.Y.Z, not '$tag'" >&2; exit 2 ;;
esac

TAP="${TAP:-waffuruai/homebrew-tap}"
TAP_URL="${TAP_URL:-https://github.com/$TAP}"
SOURCE_REPO="${SOURCE_REPO:-${GITHUB_REPOSITORY:-waffuruai/pantry}}"
branch="bump/wpantry-$tag"
path=Formula/wpantry.rb

if [ -z "${TAP_TOKEN:-}" ]; then
  echo "::warning::HOMEBREW_TAP_TOKEN is unset; the tap was not bumped for $tag. Copy the homebrew-formula artifact to $TAP as $path."
  exit 0
fi

export GH_TOKEN="$TAP_TOKEN"
export GIT_CONFIG_COUNT=3
export GIT_CONFIG_KEY_0=credential.helper GIT_CONFIG_VALUE_0='!gh auth git-credential'
export GIT_CONFIG_KEY_1=user.name GIT_CONFIG_VALUE_1='github-actions[bot]'
export GIT_CONFIG_KEY_2=user.email GIT_CONFIG_VALUE_2='41898282+github-actions[bot]@users.noreply.github.com'

formula="$(cd "$(dirname "$formula")" && pwd)/$(basename "$formula")"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# The whole tap: it is one formula, and the bump branch may already be there.
git clone --quiet --branch main "$TAP_URL" "$work/tap"
cd "$work/tap"

if git cat-file -e "main:$path" 2>/dev/null && git show "main:$path" | cmp -s - "$formula"; then
  echo "the tap already has wpantry $tag on main"
  exit 0
fi

# Reuse the remote bump branch when a previous run left one; otherwise start
# it from main. Either way the commit below sits on the remote tip, so the
# push is a fast-forward or it fails, and a rerun picks up from here.
if git rev-parse -q --verify "refs/remotes/origin/$branch" >/dev/null; then
  echo "reusing the tap's $branch"
  git checkout --quiet -b "$branch" "origin/$branch"
else
  git checkout --quiet -b "$branch"
fi

mkdir -p "$(dirname "$path")"
cp "$formula" "$path"
if [ -z "$(git status --porcelain -- "$path")" ]; then
  echo "$branch already carries this formula"
else
  git add "$path"
  git commit --quiet -m "wpantry $tag"
  git push --quiet origin "$branch"
  echo "pushed $branch to $TAP"
fi

url="$(gh pr list --repo "$TAP" --head "$branch" --base main --state open --json url --jq '.[0].url // empty')"
if [ -n "$url" ]; then
  echo "the bump PR is already open: $url"
  exit 0
fi
gh pr create --repo "$TAP" --base main --head "$branch" \
  --title "wpantry $tag" \
  --body "Formula for https://github.com/$SOURCE_REPO/releases/tag/$tag, rendered from its SHA256SUMS by the release workflow (packaging/homebrew/bump.sh)."
