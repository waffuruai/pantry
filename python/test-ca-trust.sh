#!/usr/bin/env bash
#
# Cover check-ca-trust.sh --bundle and fix-ca-trust.sh against
# a bundle that still holds the distrusted roots and one that never did.
#
# Run directly; CI runs it on Linux and macOS.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="$SCRIPT_DIR/check-ca-trust.sh"
FIX="$SCRIPT_DIR/fix-ca-trust.sh"
ROOTS="$SCRIPT_DIR/distrusted-ca/roots.pem"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() {
  echo "✗ $1" >&2
  exit 1
}

same() {
  [ "$(cat "$1")" = "$(cat "$2")" ]
}

# An unrelated self-signed root: a bundle that never trusted eMudhra.
openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=waffuru test root" -days 1 \
  -keyout "$tmp/key.pem" -out "$tmp/clean.pem" >/dev/null 2>&1

# Passes even where the system store still trusts eMudhra: the check must read
# only the bundle it is given.
"$CHECK" --bundle "$tmp/clean.pem" >/dev/null || fail "a clean bundle should pass"
echo "✓ a clean bundle passes"

"$CHECK" --bundle "$ROOTS" >/dev/null && fail "the distrusted roots should fail"
echo "✓ a bundle with the distrusted roots fails"

{
  echo "##"
  echo "## test bundle"
  echo "=== waffuru test root"
  cat "$tmp/clean.pem"
  cat "$ROOTS"
} > "$tmp/bundle.pem"
cp "$tmp/bundle.pem" "$tmp/original.pem"

CA_BUNDLE="$tmp/bundle.pem" "$FIX" >/dev/null
"$CHECK" --bundle "$tmp/bundle.pem" >/dev/null || fail "the fixed bundle should pass"
[ "$(grep -c 'BEGIN CERTIFICATE' "$tmp/bundle.pem")" -eq 1 ] || fail "the fix should keep the unrelated root"
grep -q '^=== waffuru test root$' "$tmp/bundle.pem" || fail "the fix should keep the kept entry's header"
same "$tmp/bundle.pem.orig" "$tmp/original.pem" || fail "the fix should back up the original"
echo "✓ fix-ca-trust removes the distrusted roots and keeps the rest"

CA_BUNDLE="$tmp/bundle.pem" "$FIX" >/dev/null
same "$tmp/bundle.pem.orig" "$tmp/original.pem" || fail "a second run should keep the first backup"
echo "✓ fix-ca-trust is idempotent"

echo "✓ CA trust checks: all passed"
