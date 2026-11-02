#!/usr/bin/env bash
#
# Point the Homebrew formula at a release: rewrite the tag in every `url` and
# each `sha256` from the release's SHA256SUMS (the asset a digest belongs to
# is the comment after it). Idempotent. With --check, change nothing and exit
# 1 if the formula doesn't already match. A SHA256SUMS with a malformed
# record, or an asset listed twice, is rejected whole before anything is
# written.
#
#   bump.sh [--check] [-o OUT] FORMULA TAG SHA256SUMS
#
# TAG is vX.Y.Z. OUT (default: FORMULA in place) receives the result, so the
# release workflow can render Formula/wpantry.rb for the tap from
# packaging/homebrew/wpantry.rb.

set -euo pipefail

usage() {
  echo "usage: $0 [--check] [-o OUT] FORMULA TAG SHA256SUMS" >&2
  exit 2
}

check=0
out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --check) check=1; shift ;;
    -o) [ $# -ge 2 ] || usage; out="$2"; shift 2 ;;
    -h | --help) usage ;;
    --) shift; break ;;
    -*) usage ;;
    *) break ;;
  esac
done
[ $# -eq 3 ] || usage
formula="$1" tag="$2" sums="$3"
[ -n "$out" ] || out="$formula"

case "$tag" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *) echo "bump: TAG must be vX.Y.Z, not '$tag'" >&2; exit 2 ;;
esac
[ -f "$formula" ] || { echo "bump: no formula at $formula" >&2; exit 2; }
[ -f "$sums" ] || { echo "bump: no SHA256SUMS at $sums" >&2; exit 2; }

tmp="$(mktemp)" map="$(mktemp)"
trap 'rm -f "$tmp" "$map"' EXIT

# Parse SHA256SUMS once, strictly, into the map rendering reads: one
# `<64 hex>  <asset>` record per asset (sha256sum's text form; its binary
# form, `*<asset>`, is accepted too). Anything else is a malformed manifest:
# a record that isn't two fields, a digest that isn't 64 hex characters, or
# an asset listed twice, whether or not the digests agree. Validating a
# different lookup than the one that renders is how a bad record slips in.
if ! awk -v sums="$sums" '
  function bad(why) { printf "bump: %s line %d %s: %s\n", sums, NR, why, $0 > "/dev/stderr"; failed = 1 }
  {
    if (NF != 2) { bad("is not \"<sha256>  <asset>\""); next }
    if (length($1) != 64 || $1 !~ /^[0-9a-f]+$/) { bad("has a malformed digest"); next }
    asset = $2
    sub(/^\*/, "", asset)
    if (asset == "") { bad("names no asset"); next }
    if (asset in digest) { bad(digest[asset] == $1 ? "repeats " asset : "lists " asset " again with another digest"); next }
    digest[asset] = $1
    print asset, $1
  }
  END { exit failed }
' "$sums" > "$map"; then
  exit 1
fi

# Every asset the formula names must have a record.
assets="$(sed -n 's/^ *sha256 "[^"]*" *# *\(wpantry-[A-Za-z0-9_.-]*\) *$/\1/p' "$formula" | sort -u)"
[ -n "$assets" ] || { echo "bump: $formula has no 'sha256 \"…\" # wpantry-<target>' lines" >&2; exit 2; }
for a in $assets; do
  if ! awk -v a="$a" '$1 == a { found = 1 } END { exit !found }' "$map"; then
    echo "bump: $sums has no line for $a" >&2
    exit 1
  fi
done

# The tag in each url: /releases/download/vX.Y.Z/<asset>. The digest on each
# sha256 line: looked up in the map by the asset its comment names.
awk -v tag="$tag" '
  NR == FNR { digest[$1] = $2; next }
  /^ *url "/ {
    sub(/\/releases\/download\/v[0-9][0-9A-Za-z.+-]*\//, "/releases/download/" tag "/")
  }
  /^ *sha256 "[^"]*" *# *wpantry-/ {
    asset = $0
    sub(/^.*# */, "", asset)
    sub(/ *$/, "", asset)
    if (asset in digest) sub(/sha256 "[^"]*"/, "sha256 \"" digest[asset] "\"")
  }
  { print }
' "$map" "$formula" > "$tmp"

if [ "$check" -eq 1 ]; then
  if cmp -s "$tmp" "$formula"; then
    echo "✓ $formula matches $tag and $sums"
  else
    echo "✗ $formula does not match $tag and $sums:" >&2
    diff -u "$formula" "$tmp" >&2 || true
    exit 1
  fi
else
  # Only touch the output when it changes (a no-op bump leaves mtimes alone).
  if [ -f "$out" ] && cmp -s "$tmp" "$out"; then
    echo "✓ $out already at $tag"
  else
    cp "$tmp" "$out"
    echo "✓ $out: $tag, $(printf '%s\n' "$assets" | wc -l | tr -d ' ') digests from $sums"
  fi
fi
