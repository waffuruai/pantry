#!/usr/bin/env bash
#
# Output helpers shared by check-ca-trust.sh and fix-ca-trust.sh. Sourced, not
# run.

is_macos() {
  [ "$(uname -s)" = "Darwin" ]
}

print_header() {
  echo
  echo "==> $*"
}

ok() {
  echo "✓ $*"
}

warn() {
  echo "⚠ $*" >&2
}

fail() {
  echo "✗ $*" >&2
  exit 1
}

# One aligned line: label, value, mark (ok | warn | fail | info) and a note.
status_line() {
  local label="$1" value="$2" state="$3" extra="${4:-}" mark
  case "$state" in
    ok) mark="✓" ;;
    warn) mark="⚠" ;;
    fail) mark="✗" ;;
    *) mark="·" ;;
  esac
  printf "  %-8s %-40s %s%s\n" "$label" "$value" "$mark" "${extra:+  $extra}"
}

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "'$1' not found.${2:+ $2}"
}
