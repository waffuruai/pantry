#!/usr/bin/env bash
#
# Fail when a trust store on this machine still trusts an intermediate CA in
# distrusted-ca/ (today: the eMudhra intermediates whose private keys leaked,
# https://emudhra.we-have-a-problem.com/). bin/wscanner runs it before every
# machine scan.
#
# A store fails when openssl can build a path from one of those intermediates
# to a root it holds, which is the trust decision every OpenSSL-, LibreSSL-,
# pip- or Node-based client makes. Rust crates that embed roots (webpki-roots)
# are covered by the CVE scan, bin/wscanner.py.
#
# Usage: check-ca-trust.sh [--bundle FILE]   (--bundle checks one PEM bundle)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ca-common.sh
source "$SCRIPT_DIR/ca-common.sh"

CA_DIR="$SCRIPT_DIR/distrusted-ca"

require_cmd openssl

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# One file per intermediate: openssl verify reads only the first certificate
# in a file.
awk -v d="$tmp" '
  /-----BEGIN CERTIFICATE-----/ { n++; f = sprintf("%s/int%02d.pem", d, n) }
  f { print > f }
  /-----END CERTIFICATE-----/ { close(f); f = "" }
' "$CA_DIR/intermediates.pem"

# Empty default locations: openssl verify still reads the system store next to
# an explicit -CAfile or -CApath (Fedora does), which would blame that store
# on the one under test. OpenSSL and LibreSSL both honour these variables.
mkdir "$tmp/empty"
: > "$tmp/empty.pem"

# 0 when the anchors (a PEM bundle, or a hashed directory like /etc/ssl/certs)
# chain any distrusted intermediate to one of their roots.
bundle_trusts() {
  local opt="-CAfile" c
  [ -d "$1" ] && opt="-CApath"
  for c in "$tmp"/int*.pem; do
    if SSL_CERT_FILE="$tmp/empty.pem" SSL_CERT_DIR="$tmp/empty" SSL_CERT_URI="file:$tmp/empty" \
      openssl verify "$opt" "$1" -untrusted "$CA_DIR/issuers.pem" "$c" >/dev/null 2>&1; then
      return 0
    fi
  done
  return 1
}

if [ "${1:-}" = "--bundle" ]; then
  [ -e "${2:-}" ] || fail "no such bundle: ${2:-}"
  if bundle_trusts "$2"; then
    echo "✗ $2 trusts a distrusted intermediate"
    exit 1
  fi
  echo "✓ $2 rejects every distrusted intermediate"
  exit 0
fi

failed=0
seen="$tmp/seen"
: > "$seen"

# check_bundle <label> <shown as> <bundle> [hint]
check_bundle() {
  local label="$1" shown="$2" bundle="$3" hint="${4:-}" real
  if [ -d "$bundle" ]; then
    compgen -G "$bundle/*.0" >/dev/null || return 0
  else
    [ -s "$bundle" ] || return 0
  fi
  real="$(realpath "$bundle" 2>/dev/null || echo "$bundle")"
  grep -qxF "$real" "$seen" && return 0
  echo "$real" >> "$seen"
  if bundle_trusts "$bundle"; then
    status_line "$label" "$shown" fail "trusts the leaked eMudhra CAs${hint:+. $hint}"
    failed=1
  else
    status_line "$label" "$shown" ok
  fi
}

print_header "CA trust (distrusted CAs in $CA_DIR)"

if is_macos; then
  check_bundle "system" /etc/ssl/cert.pem /etc/ssl/cert.pem "Run: $SCRIPT_DIR/fix-ca-trust.sh"
else
  for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem /etc/ssl/certs; do
    check_bundle "system" "$f" "$f" "Update the ca-certificates package, or run: $SCRIPT_DIR/fix-ca-trust.sh"
  done
fi

ossl_dir="$(openssl version -d 2>/dev/null | sed -n 's/^OPENSSLDIR: "\(.*\)"$/\1/p')"
if [ -n "$ossl_dir" ]; then
  for f in "$ossl_dir/cert.pem" "$ossl_dir/certs"; do
    check_bundle "openssl" "$f" "$f" "Update the store $(command -v openssl) reads"
  done
fi

if command -v brew >/dev/null 2>&1; then
  brew_ca="$(brew --prefix)/etc/ca-certificates/cert.pem"
  check_bundle "brew" "$brew_ca" "$brew_ca" "Run: brew upgrade ca-certificates"
fi

# Every python3 on PATH, plus Xcode's (only when the developer tools exist, so
# /usr/bin/python3 can't pop the Command Line Tools installer).
pythons="$(type -ap python3 || true)"
if is_macos && xcode-select -p >/dev/null 2>&1; then
  pythons="$pythons"$'\n'/usr/bin/python3
fi
while IFS= read -r py; do
  [ -n "$py" ] || continue
  certifi="$("$py" -I -c 'import certifi; print(certifi.where())' 2>/dev/null || true)"
  check_bundle "certifi" "$certifi" "$certifi" "Run: $py -m pip install -U certifi"
  pip_ca="$("$py" -I -c 'import pip._vendor.certifi as c; print(c.where())' 2>/dev/null || true)"
  [ -n "$pip_ca" ] || continue
  # pip reads PIP_CERT instead of its own bundle when it is set.
  if [ -n "${PIP_CERT:-}" ] && [ -f "$PIP_CERT" ] && ! bundle_trusts "$PIP_CERT"; then
    grep -qxF "$pip_ca" "$seen" && continue
    echo "$pip_ca" >> "$seen"
    status_line "pip" "$pip_ca" ok "PIP_CERT=$PIP_CERT overrides it"
    continue
  fi
  check_bundle "pip" "$pip_ca" "$pip_ca" "Run: $py -m pip install -U pip, or export PIP_CERT=$(brew --prefix 2>/dev/null || echo /path/to)/etc/ca-certificates/cert.pem"
done <<< "$pythons"

# Node compiles its roots in; dump them to check like any other bundle.
i=0
while IFS= read -r node; do
  [ -n "$node" ] || continue
  i=$((i + 1))
  "$node" -p "require('tls').rootCertificates.join('\n')" > "$tmp/node$i.pem" 2>/dev/null || continue
  check_bundle "node" "$node ($("$node" --version 2>/dev/null))" "$tmp/node$i.pem" "Upgrade Node (26.12.1, 24.22.1, 22.23.4 or later)"
done <<< "$(type -ap node || true)"

# The macOS trust settings that Safari, URLSession and Go use. -L: local
# decisions only, no network.
if is_macos; then
  keychain=ok
  for c in "$tmp"/int*.pem; do
    if security verify-cert -L -q -p basic -c "$c" -c "$CA_DIR/issuers.pem" >/dev/null 2>&1; then
      keychain=fail
    fi
  done
  if [ "$keychain" = ok ]; then
    status_line "keychain" "macOS trust settings" ok
  else
    status_line "keychain" "macOS trust settings" fail "trusts the leaked eMudhra CAs. Install the latest macOS update"
    failed=1
  fi
fi

if [ "$failed" -ne 0 ]; then
  warn "a trust store above still trusts a distrusted CA (see https://emudhra.we-have-a-problem.com/)."
  exit 1
fi
ok "no trust store accepts a distrusted CA"
