#!/bin/sh
#
# packaging/homebrew/tap-pr.sh against a local bare "tap" and a stub gh:
# without a token it warns and touches nothing; with one it pushes the bump
# branch and opens the PR; rerun, it reuses the branch, commits nothing and
# finds the open PR instead of creating another; after a failed `gh pr
# create` the rerun opens the PR without re-pushing; a changed formula lands
# as a fast-forward commit on the existing branch; a tap whose main already
# has the formula gets no branch. The bare repository denies non-fast-forward
# pushes, so a force-push anywhere would fail the test. Run directly; `mise
# run test packaging` and CI run it.

set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TAP_PR="$ROOT/packaging/homebrew/tap-pr.sh"
FORMULA="$ROOT/packaging/homebrew/wpantry.rb"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() {
  echo "✗ $1" >&2
  exit 1
}

# A stub gh: logs every call; `pr list --head B` prints the URL of the PR
# recorded for B, if any; `pr create --head B` records one, or fails when
# GH_FAIL_CREATE=1 (the transient API failure the rerun must recover from).
mkdir -p "$tmp/bin"
cat > "$tmp/bin/gh" <<'STUB'
#!/bin/sh
echo "$*" >> "$GH_LOG"
head=""
while [ $# -gt 0 ]; do
  case "$1" in
    --head) head="$2"; shift 2 ;;
    pr|list|create|auth|git-credential) sub="${sub:-}$1 "; shift ;;
    *) shift ;;
  esac
done
case "$sub" in
  "pr list ") grep -F -x -- "$head" "$GH_PRS" >/dev/null 2>&1 && echo "https://example.invalid/$head/pull/1"; exit 0 ;;
  "pr create ") [ "${GH_FAIL_CREATE:-0}" = 1 ] && { echo "stub gh: API failure" >&2; exit 1; }
               echo "$head" >> "$GH_PRS"; echo "https://example.invalid/$head/pull/1"; exit 0 ;;
  "auth git-credential ") exit 0 ;;
  *) echo "stub gh: unexpected: $sub" >&2; exit 1 ;;
esac
STUB
chmod +x "$tmp/bin/gh"
PATH="$tmp/bin:$PATH"
GH_LOG="$tmp/gh.log" GH_PRS="$tmp/gh.prs"
export PATH GH_LOG GH_PRS
: > "$GH_LOG"
: > "$GH_PRS"

# The tap: main with a README and the formula at its committed release.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@example.invalid GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@example.invalid
git init -q --bare -b main "$tmp/tap.git"
git -C "$tmp/tap.git" config receive.denyNonFastForwards true
git clone -q "$tmp/tap.git" "$tmp/seed" 2>/dev/null
mkdir -p "$tmp/seed/Formula"
echo "brew install waffuruai/tap/wpantry" > "$tmp/seed/README.md"
cp "$FORMULA" "$tmp/seed/Formula/wpantry.rb"
git -C "$tmp/seed" add -A
git -C "$tmp/seed" commit -q -m "wpantry"
git -C "$tmp/seed" push -q origin HEAD:main
rm -rf "$tmp/seed"

remote_sha() { git -C "$tmp/tap.git" rev-parse -q --verify "refs/heads/$1" 2>/dev/null || true; }
remote_formula() { git -C "$tmp/tap.git" show "refs/heads/$1:Formula/wpantry.rb"; }
creates() { grep -c '^pr create ' "$GH_LOG" | tr -d ' '; }
prs() { grep -c . "$GH_PRS" | tr -d ' '; }

# A rendered formula for v9.9.9 (any content that differs from main's).
sed 's|/releases/download/v[0-9][^/]*/|/releases/download/v9.9.9/|' "$FORMULA" > "$tmp/v9.9.9.rb"
cmp -s "$FORMULA" "$tmp/v9.9.9.rb" && fail "the test formula should differ from the committed one"
b=bump/wpantry-v9.9.9
export TAP=waffuruai/homebrew-tap TAP_URL="$tmp/tap.git" SOURCE_REPO=waffuruai/pantry

# No token: a warning, nothing pushed, gh never called.
TAP_TOKEN='' "$TAP_PR" "$tmp/v9.9.9.rb" v9.9.9 > "$tmp/out" || fail "an unset token must not fail the job"
grep -q '^::warning::HOMEBREW_TAP_TOKEN is unset' "$tmp/out" || fail "an unset token should warn"
[ -z "$(remote_sha "$b")" ] || fail "an unset token must not push"
[ ! -s "$GH_LOG" ] || fail "an unset token must not call gh"

# With the token: the branch is pushed with the formula, one commit on main, and the PR opened.
TAP_TOKEN=secret "$TAP_PR" "$tmp/v9.9.9.rb" v9.9.9 > "$tmp/out" || fail "the first run failed"
sha1="$(remote_sha "$b")"
[ -n "$sha1" ] || fail "the first run should push $b"
remote_formula "$b" | cmp -s - "$tmp/v9.9.9.rb" || fail "$b should carry the rendered formula"
[ "$(git -C "$tmp/tap.git" rev-parse "$b^")" = "$(remote_sha main)" ] || fail "$b should be one commit on main"
[ "$(creates)" = 1 ] || fail "the first run should create the PR once"
grep -q '^pr create .*--title wpantry v9.9.9' "$GH_LOG" || fail "the PR title should name the tag"
grep -q 'releases/tag/v9.9.9' "$GH_LOG" || fail "the PR body should link the release"

# Rerun, same formula: the branch is reused, nothing committed, the PR found.
TAP_TOKEN=secret "$TAP_PR" "$tmp/v9.9.9.rb" v9.9.9 > "$tmp/out" || fail "the rerun failed"
[ "$(remote_sha "$b")" = "$sha1" ] || fail "a rerun with the same formula must not commit"
[ "$(creates)" = 1 ] || fail "a rerun must not open a second PR"
grep -q "already open: https://example.invalid/$b/pull/1" "$tmp/out" || fail "the rerun should report the open PR"
grep -q "reusing the tap's $b" "$tmp/out" || fail "the rerun should say it reused the branch"

# The push succeeded but `gh pr create` failed: the rerun opens the PR on the
# branch already there, without a second commit or a non-fast-forward push.
sed 's|/releases/download/v[0-9][^/]*/|/releases/download/v9.9.10/|' "$FORMULA" > "$tmp/v9.9.10.rb"
b10=bump/wpantry-v9.9.10
if GH_FAIL_CREATE=1 TAP_TOKEN=secret "$TAP_PR" "$tmp/v9.9.10.rb" v9.9.10 >/dev/null 2>&1; then fail "a failed gh pr create should fail the run"; fi
sha10="$(remote_sha "$b10")"
[ -n "$sha10" ] || fail "the branch should have been pushed before gh pr create failed"
grep -q -x "$b10" "$GH_PRS" && fail "no PR should be recorded after the failed create"
TAP_TOKEN=secret "$TAP_PR" "$tmp/v9.9.10.rb" v9.9.10 > "$tmp/out" || fail "the rerun after a failed gh pr create failed"
[ "$(remote_sha "$b10")" = "$sha10" ] || fail "the rerun must not recreate or re-push the branch"
grep -q -x "$b10" "$GH_PRS" || fail "the rerun should open the PR"
grep -q "already carries this formula" "$tmp/out" || fail "the rerun should find nothing to commit"

# A different render for the same tag: one more commit, fast-forward, PR kept.
sed 's/sha256 "[0-9a-f]*"/sha256 "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"/' "$tmp/v9.9.9.rb" > "$tmp/v9.9.9b.rb"
TAP_TOKEN=secret "$TAP_PR" "$tmp/v9.9.9b.rb" v9.9.9 > "$tmp/out" || fail "the changed-formula run failed"
sha2="$(remote_sha "$b")"
[ "$sha2" != "$sha1" ] || fail "a changed formula should be committed"
[ "$(git -C "$tmp/tap.git" rev-parse "$sha2^")" = "$sha1" ] || fail "the new commit should sit on the branch's previous tip"
remote_formula "$b" | cmp -s - "$tmp/v9.9.9b.rb" || fail "$b should carry the new formula"
[ "$(prs)" = 2 ] || fail "the changed-formula run must not open another PR for $b"

# main already has the formula: no branch, no gh call.
: > "$GH_LOG"
TAP_TOKEN=secret "$TAP_PR" "$FORMULA" v0.0.1 > "$tmp/out" || fail "a tap already at the release should exit 0"
grep -q "already has wpantry v0.0.1 on main" "$tmp/out" || fail "a tap already at the release should say so"
[ -z "$(remote_sha bump/wpantry-v0.0.1)" ] || fail "a tap already at the release must get no branch"
[ ! -s "$GH_LOG" ] || fail "a tap already at the release must not call gh"

# Usage errors.
if "$TAP_PR" "$tmp/v9.9.9.rb" >/dev/null 2>&1; then fail "missing arguments should be a usage error"; fi
if TAP_TOKEN=secret "$TAP_PR" "$tmp/v9.9.9.rb" 9.9.9 >/dev/null 2>&1; then fail "a tag without v should be an error"; fi
if TAP_TOKEN=secret "$TAP_PR" "$tmp/missing.rb" v9.9.9 >/dev/null 2>&1; then fail "a missing formula should be an error"; fi

echo "✓ tap-pr.sh: warns without a token, pushes and opens the PR, reruns reuse the branch and the PR, never force-pushes"
