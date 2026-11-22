#!/usr/bin/env bash
# Time and peak memory of loading a rules directory: compiled from source,
# then read back from the compiled bundle that compile writes. Prints one
# line for each, so a regression in either shows.
#
#   scripts/yara-bench.sh [RULES_DIR]
#
# RULES_DIR defaults to Pantry's rules directory (~/.cache/wpantry/rules,
# or $XDG_CACHE_HOME/wpantry/rules). Nothing in it is changed: the bundle
# is written to a temp file.
set -euo pipefail

rules=${1:-${XDG_CACHE_HOME:-$HOME/.cache}/wpantry/rules}
root="$(cd "$(dirname "$0")/.." && pwd)"
[ -d "$rules" ] || { echo "no rules directory at $rules (run a malware scan or wpantry rules --update first)" >&2; exit 2; }

(cd "$root/rust" && env -u RUSTUP_TOOLCHAIN cargo build --locked --release -q -p wpantry-yara --example compile_rules)
bin="$root/rust/target/release/examples/compile_rules"
bundle="$(mktemp)"
trap 'rm -f "$bundle"' EXIT

# Peak resident memory of a command, in MB: BSD time on macOS, GNU on Linux.
peak() {
    local out
    if [ "$(uname)" = Darwin ]; then
        out="$( { /usr/bin/time -l "$@" >/dev/null; } 2>&1 )"
        echo "$out" | grep -E 'Stats' | sed 's/^/  /'
        echo "$out" | awk '/maximum resident set size/ { printf "  peak %d MB\n", $1 / 1048576 }'
    else
        out="$( { /usr/bin/time -v "$@" >/dev/null; } 2>&1 )"
        echo "$out" | grep -E 'Stats' | sed 's/^/  /'
        echo "$out" | awk -F: '/Maximum resident set size/ { printf "  peak %d MB\n", $2 / 1024 }'
    fi
}

echo "from source ($rules):"
peak "$bin" "$rules" --write "$bundle"
echo "from the compiled bundle ($(( $(wc -c < "$bundle") / 1048576 )) MB):"
peak "$bin" "$rules" --read "$bundle"
