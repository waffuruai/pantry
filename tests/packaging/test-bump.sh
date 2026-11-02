#!/bin/sh
#
# packaging/homebrew/bump.sh against a copy of the formula and a fake
# SHA256SUMS: it rewrites the tag and every digest, is idempotent, --check
# tells a matching formula from a stale one, and a SHA256SUMS missing an
# asset, with a malformed record or listing an asset twice is an error. Run
# directly; `mise run test packaging` and CI run it.

set -eu

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUMP="$ROOT/packaging/homebrew/bump.sh"
FORMULA="$ROOT/packaging/homebrew/wpantry.rb"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() {
  echo "✗ $1" >&2
  exit 1
}

d1=1111111111111111111111111111111111111111111111111111111111111111
d2=2222222222222222222222222222222222222222222222222222222222222222
d3=3333333333333333333333333333333333333333333333333333333333333333
cat > "$tmp/SHA256SUMS" <<SUMS
$d1  wpantry-aarch64-unknown-linux-musl
$d2  wpantry-universal-apple-darwin
$d3  wpantry-x86_64-unknown-linux-musl
SUMS

# The committed formula is at some release: it checks against its own sums.
tag="$(sed -n 's|.*/releases/download/\(v[0-9][^/]*\)/.*|\1|p' "$FORMULA" | head -n 1)"
[ -n "$tag" ] || fail "the formula names no release tag in its urls"
sed -n 's/^ *sha256 "\([0-9a-f]*\)" *# *\(wpantry-.*\)$/\1  \2/p' "$FORMULA" | sort -u -k2 > "$tmp/own.sums"
"$BUMP" --check "$FORMULA" "$tag" "$tmp/own.sums" >/dev/null || fail "the committed formula should match its own digests at $tag"

# Bump to a new tag with new digests, to another file.
cp "$FORMULA" "$tmp/f.rb"
"$BUMP" -o "$tmp/out.rb" "$tmp/f.rb" v9.9.9 "$tmp/SHA256SUMS" >/dev/null || fail "bump -o failed"
cmp -s "$FORMULA" "$tmp/f.rb" || fail "-o must leave the input alone"
grep -q 'releases/download/v9.9.9/wpantry-universal-apple-darwin' "$tmp/out.rb" || fail "macOS url not bumped"
grep -q 'releases/download/v9.9.9/wpantry-x86_64-unknown-linux-musl' "$tmp/out.rb" || fail "x86_64 url not bumped"
grep -q 'releases/download/v9.9.9/wpantry-aarch64-unknown-linux-musl' "$tmp/out.rb" || fail "aarch64 url not bumped"
grep -q "/download/$tag/" "$tmp/out.rb" && fail "the old tag is still in the output"
[ "$(grep -c "sha256 \"$d2\" # wpantry-universal-apple-darwin" "$tmp/out.rb")" = 2 ] || fail "both macOS digests should be the universal binary's"
grep -q "sha256 \"$d3\" # wpantry-x86_64-unknown-linux-musl" "$tmp/out.rb" || fail "x86_64 digest not bumped"
grep -q "sha256 \"$d1\" # wpantry-aarch64-unknown-linux-musl" "$tmp/out.rb" || fail "aarch64 digest not bumped"
[ "$(grep -c '^ *sha256 "' "$tmp/out.rb")" = "$(grep -c '^ *sha256 "' "$FORMULA")" ] || fail "the number of sha256 lines changed"
ruby -c "$tmp/out.rb" >/dev/null 2>&1 || { command -v ruby >/dev/null 2>&1 && fail "the bumped formula isn't valid Ruby"; }

# In place, and idempotent.
"$BUMP" "$tmp/f.rb" v9.9.9 "$tmp/SHA256SUMS" >/dev/null || fail "in-place bump failed"
cmp -s "$tmp/f.rb" "$tmp/out.rb" || fail "in-place and -o results differ"
"$BUMP" "$tmp/f.rb" v9.9.9 "$tmp/SHA256SUMS" | grep -q "already at v9.9.9" || fail "a second bump should be a no-op"
cmp -s "$tmp/f.rb" "$tmp/out.rb" || fail "a second bump changed the file"

# --check: matches, then doesn't once a digest is stale.
"$BUMP" --check "$tmp/f.rb" v9.9.9 "$tmp/SHA256SUMS" >/dev/null || fail "--check should pass on a bumped formula"
sed "s/$d3/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff/" "$tmp/SHA256SUMS" > "$tmp/SHA256SUMS.new"
if "$BUMP" --check "$tmp/f.rb" v9.9.9 "$tmp/SHA256SUMS.new" >/dev/null 2>&1; then fail "--check should fail on a stale digest"; fi
if "$BUMP" --check "$tmp/f.rb" v9.9.8 "$tmp/SHA256SUMS" >/dev/null 2>&1; then fail "--check should fail on another tag"; fi
cmp -s "$tmp/f.rb" "$tmp/out.rb" || fail "--check must not write"

# Errors: an asset missing from SHA256SUMS, a malformed digest, a bad tag.
grep -v universal "$tmp/SHA256SUMS" > "$tmp/short.sums"
if "$BUMP" "$tmp/f.rb" v9.9.9 "$tmp/short.sums" >/dev/null 2>&1; then fail "a SHA256SUMS missing an asset should be an error"; fi
sed "s/$d1/nothex/" "$tmp/SHA256SUMS" > "$tmp/bad.sums"
if "$BUMP" "$tmp/f.rb" v9.9.9 "$tmp/bad.sums" >/dev/null 2>&1; then fail "a malformed digest should be an error"; fi
# sha256sum's binary form, `*asset`, is the same record.
sed 's/  wpantry-/ *wpantry-/' "$tmp/SHA256SUMS" > "$tmp/binary.sums"
"$BUMP" --check "$tmp/f.rb" v9.9.9 "$tmp/binary.sums" >/dev/null || fail "a '*asset' record should be read like an 'asset' one"
# A second record for an asset must not win over the first, whatever it says:
# rendering used the last record while validation checked the first.
{ cat "$tmp/SHA256SUMS"; echo "nothex  wpantry-aarch64-unknown-linux-musl"; } > "$tmp/dup-bad.sums"
if "$BUMP" "$tmp/f.rb" v9.9.9 "$tmp/dup-bad.sums" >/dev/null 2>&1; then fail "a malformed second record for an asset should be an error"; fi
if "$BUMP" --check "$tmp/f.rb" v9.9.9 "$tmp/dup-bad.sums" >/dev/null 2>&1; then fail "--check should reject a malformed second record too"; fi
grep -q '"nothex"' "$tmp/f.rb" && fail "a malformed second record reached the formula"
{ cat "$tmp/SHA256SUMS"; echo "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff  wpantry-aarch64-unknown-linux-musl"; } > "$tmp/dup-conflict.sums"
if "$BUMP" "$tmp/f.rb" v9.9.9 "$tmp/dup-conflict.sums" >/dev/null 2>&1; then fail "two records for an asset with different digests should be an error"; fi
{ cat "$tmp/SHA256SUMS"; head -n 1 "$tmp/SHA256SUMS"; } > "$tmp/dup-same.sums"
if "$BUMP" "$tmp/f.rb" v9.9.9 "$tmp/dup-same.sums" >/dev/null 2>&1; then fail "an asset listed twice should be an error even with the same digest"; fi
"$BUMP" "$tmp/f.rb" v9.9.9 "$tmp/dup-conflict.sums" 2>&1 >/dev/null | grep -q "wpantry-aarch64-unknown-linux-musl" || fail "the error should name the asset listed twice"
# Any malformed record poisons the manifest, not just one for a needed asset.
{ cat "$tmp/SHA256SUMS"; echo "deadbeef  wpantry-something-else"; } > "$tmp/extra-bad.sums"
if "$BUMP" "$tmp/f.rb" v9.9.9 "$tmp/extra-bad.sums" >/dev/null 2>&1; then fail "a malformed record for another asset should be an error"; fi
{ cat "$tmp/SHA256SUMS"; echo "$d1  wpantry-x y"; } > "$tmp/fields.sums"
if "$BUMP" "$tmp/f.rb" v9.9.9 "$tmp/fields.sums" >/dev/null 2>&1; then fail "a record that isn't two fields should be an error"; fi
if "$BUMP" "$tmp/f.rb" 9.9.9 "$tmp/SHA256SUMS" >/dev/null 2>&1; then fail "a tag without v should be an error"; fi
if "$BUMP" "$tmp/f.rb" v9.9.9 >/dev/null 2>&1; then fail "missing arguments should be a usage error"; fi
cmp -s "$tmp/f.rb" "$tmp/out.rb" || fail "an error must not write"

echo "✓ bump.sh: rewrites, idempotent, --check, errors, duplicate and malformed records"
