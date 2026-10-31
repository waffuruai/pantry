#!/usr/bin/env bash
#
# Point the Homebrew formula at a release: rewrite the tag in every `url` and
# each `sha256` from the release's SHA256SUMS (the asset a digest belongs to
# is the comment after it). Idempotent. With --check, change nothing and exit
# 1 if the formula doesn't already match.
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

# Every asset the formula names must be in SHA256SUMS, with a 64-hex digest.
assets="$(sed -n 's/^ *sha256 "[^"]*" *# *\(wpantry-[A-Za-z0-9_.-]*\) *$/\1/p' "$formula" | sort -u)"
[ -n "$assets" ] || { echo "bump: $formula has no 'sha256 \"…\" # wpantry-<target>' lines" >&2; exit 2; }
for a in $assets; do
  d="$(awk -v a="$a" '$2 == a { print $1 }' "$sums" | head -n 1)"
  if [ -z "$d" ]; then
    echo "bump: $sums has no line for $a" >&2
    exit 1
  fi
  if ! printf '%s\n' "$d" | grep -Eq '^[0-9a-f]{64}$'; then
    echo "bump: $sums has a malformed digest for $a: $d" >&2
    exit 1
  fi
done

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
# The tag in each url: /releases/download/vX.Y.Z/<asset>. The digest on each
# sha256 line: looked up by the asset its comment names.
awk -v tag="$tag" -v sums="$sums" '
  BEGIN {
    while ((getline line < sums) > 0) {
      split(line, f, /[ \t]+/)
      if (f[2] != "") digest[f[2]] = f[1]
    }
    close(sums)
  }
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
' "$formula" > "$tmp"

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
