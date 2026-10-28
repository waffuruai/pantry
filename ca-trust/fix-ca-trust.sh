#!/usr/bin/env bash
#
# Distrust the roots in the crate's distrusted-ca/roots.pem in the system trust
# store, the advisory's workaround (https://emudhra.we-have-a-problem.com/)
# matched by fingerprint. Needs root (uses sudo). Updating the OS's
# ca-certificates package is the real fix; this is for until it ships.
#
#   macOS   rewrites /etc/ssl/cert.pem, which OpenSSL and LibreSSL tools read
#           and macOS updates have not fixed. The original is kept once as
#           cert.pem.orig; a macOS update may restore the file, so re-run
#           after one (wpantry says).
#   Linux   uses the distro's own mechanism, so its next trust store rebuild
#           keeps the roots out: `!` lines in /etc/ca-certificates.conf
#           (Debian, Ubuntu, Alpine) or the p11-kit blocklist (Fedora, RHEL,
#           Arch, openSUSE, SLES), then rebuilds the store.
#
# CA_BUNDLE=FILE rewrites that PEM bundle instead, as on macOS (the tests use
# it).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=ca-common.sh
source "$SCRIPT_DIR/ca-common.sh"

# The certificates the wpantry crate embeds, so there is one copy.
CA_DIR="$(cd "$SCRIPT_DIR/../rust/crates/wpantry/assets/distrusted-ca" && pwd)"

require_cmd openssl

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

as_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    sudo "$@"
  fi
}

fingerprint() {
  openssl x509 -in "$1" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d :
}

# Split into entries: each certificate with the comment lines above it.
split_entries() {
  awk -v d="$2" '
    { if (!f) { n++; f = sprintf("%s/%04d.pem", d, n) } print > f }
    /-----END CERTIFICATE-----/ { close(f); f = "" }
  ' "$1"
}

mkdir "$tmp/roots"
split_entries "$CA_DIR/roots.pem" "$tmp/roots"
for r in "$tmp"/roots/*.pem; do
  fingerprint "$r"
done | grep . > "$tmp/drop"

is_distrusted() {
  local fp
  fp="$(fingerprint "$1")"
  [ -n "$fp" ] && grep -qxF "$fp" "$tmp/drop"
}

# Fail unless every existing system store now rejects the distrusted CAs.
verify_system() {
  local f
  for f in "$@"; do
    [ -e "$f" ] || continue
    "$SCRIPT_DIR/check-ca-trust.sh" --bundle "$f" >/dev/null ||
      fail "$f still trusts a distrusted CA"
  done
}

fix_bundle() {
  local target="$1" e removed=0 before after
  [ -f "$target" ] || fail "no such bundle: $target"
  mkdir "$tmp/entries"
  split_entries "$target" "$tmp/entries"
  : > "$tmp/bundle.pem"
  for e in "$tmp"/entries/*.pem; do
    if is_distrusted "$e"; then
      removed=$((removed + 1))
      echo "  removing $(openssl x509 -in "$e" -noout -subject 2>/dev/null)"
      continue
    fi
    cat "$e" >> "$tmp/bundle.pem"
  done

  if [ "$removed" -eq 0 ]; then
    ok "$target holds none of the distrusted roots"
    return
  fi

  # Never install a bundle that lost more than the roots, or still trusts them.
  before="$(grep -c 'BEGIN CERTIFICATE' "$target")"
  after="$(grep -c 'BEGIN CERTIFICATE' "$tmp/bundle.pem" || true)"
  [ "$after" -eq $((before - removed)) ] || fail "rewrite kept $after of $before certificates; leaving $target alone"
  "$SCRIPT_DIR/check-ca-trust.sh" --bundle "$tmp/bundle.pem" >/dev/null ||
    fail "the rewritten bundle still trusts a distrusted CA; leaving $target alone"

  if [ -w "$target" ] && [ -w "$(dirname "$target")" ]; then
    [ -e "$target.orig" ] || cp -p "$target" "$target.orig"
    cat "$tmp/bundle.pem" > "$target"
  else
    [ -e "$target.orig" ] || as_root cp -p "$target" "$target.orig"
    as_root install -m 0644 -o root -g "$(id -gn root)" "$tmp/bundle.pem" "$target"
  fi
  ok "removed $removed distrusted root(s) from $target (original: $target.orig)"
}

# Debian, Ubuntu, Alpine: deselect each matching certificate with a `!` line,
# which update-ca-certificates honours on every rebuild.
fix_ca_certificates_conf() {
  local conf=/etc/ca-certificates.conf share=/usr/share/ca-certificates f rel n=0
  cp "$conf" "$tmp/conf"
  while IFS= read -r f; do
    is_distrusted "$f" || continue
    rel="${f#"$share"/}"
    echo "  distrusting $rel"
    awk -v rel="$rel" '$0 == rel { $0 = "!" rel } { print }' "$tmp/conf" > "$tmp/conf.new"
    grep -qxF "!$rel" "$tmp/conf.new" || echo "!$rel" >> "$tmp/conf.new"
    mv "$tmp/conf.new" "$tmp/conf"
    n=$((n + 1))
  done < <(find "$share" -name '*.crt' 2>/dev/null)

  for f in /usr/local/share/ca-certificates/*.crt; do
    [ -f "$f" ] && is_distrusted "$f" && fail "$f adds a distrusted root by hand; remove it, then re-run"
  done

  if [ "$n" -eq 0 ]; then
    ok "the system store holds none of the distrusted roots"
    return
  fi
  [ -e "$conf.orig" ] || as_root cp -p "$conf" "$conf.orig"
  as_root install -m 0644 "$tmp/conf" "$conf"
  as_root update-ca-certificates >/dev/null
  verify_system /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/ssl/certs
  ok "distrusted $n root(s) in $conf (original: $conf.orig)"
}

# Fedora, RHEL, Arch, openSUSE: drop the roots into the p11-kit blocklist.
fix_blocklist() {
  local dir="$1" r fp
  shift
  as_root mkdir -p "$dir"
  for r in "$tmp"/roots/*.pem; do
    fp="$(fingerprint "$r")"
    as_root install -m 0644 "$r" "$dir/waffuru-distrusted-${fp:0:16}.pem"
  done
  as_root "$@" >/dev/null
  verify_system /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem /etc/ssl/certs
  ok "blocklisted the distrusted roots in $dir"
}

# <parent>/blocklist, or the older <parent>/blacklist where only that exists.
blocklist_dir() {
  if [ -d "$1/blacklist" ] && [ ! -d "$1/blocklist" ]; then
    echo "$1/blacklist"
  else
    echo "$1/blocklist"
  fi
}

if [ -n "${CA_BUNDLE:-}" ]; then
  fix_bundle "$CA_BUNDLE"
elif is_macos; then
  fix_bundle /etc/ssl/cert.pem
elif [ -d /etc/pki/trust ]; then
  fix_blocklist "$(blocklist_dir /etc/pki/trust)" update-ca-certificates
elif [ -d /etc/pki/ca-trust/source ]; then
  fix_blocklist "$(blocklist_dir /etc/pki/ca-trust/source)" update-ca-trust extract
elif [ -d /etc/ca-certificates/trust-source ]; then
  fix_blocklist /etc/ca-certificates/trust-source/blocklist update-ca-trust extract
elif [ -f /etc/ca-certificates.conf ] && command -v update-ca-certificates >/dev/null 2>&1; then
  fix_ca_certificates_conf
else
  fail "don't know this system's trust store. Update its ca-certificates package (see https://emudhra.we-have-a-problem.com/)."
fi
