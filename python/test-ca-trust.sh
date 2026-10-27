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
out="$("$CHECK" --bundle "$tmp/clean.pem" 2>&1)" || {
  # Show what the check said: this has failed on a CI macOS runner where the
  # same test passes locally, and the cause is invisible without its output.
  printf '%s\n' "$out" >&2
  # Diagnostics for the runner-only failure: which intermediate verified
  # against a self-signed throwaway root, and with what clock and validity.
  {
    openssl version -a | head -3
    date -u
    openssl x509 -in "$tmp/clean.pem" -noout -subject -dates
    d="$(mktemp -d)"
    awk -v d="$d" '/-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/int%02d.pem", d, n) } f { print > f } /-----END CERTIFICATE-----/ { close(f); f = "" }' "$(dirname "$CHECK")/distrusted-ca/intermediates.pem"
    for c in "$d"/int*.pem; do
      printf '%s: ' "$(basename "$c")"
      SSL_CERT_FILE=/dev/null SSL_CERT_DIR=/nonexistent openssl verify -CAfile "$tmp/clean.pem" -untrusted "$(dirname "$CHECK")/distrusted-ca/issuers.pem" "$c" 2>&1 | tail -1
    done
    rm -rf "$d"
  } >&2 || true
  fail "a clean bundle should pass"
}
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
