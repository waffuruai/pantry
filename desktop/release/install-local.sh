#!/usr/bin/env bash
#
# Build Pantry Desktop and its scanner from this checkout, package them the
# way the release workflow does (.github/workflows/release.yml), and install
# the result for this account with Pantry Setup.
#
#   desktop/release/install-local.sh              build, then install
#   desktop/release/install-local.sh --open       build, install, open Pantry
#   desktop/release/install-local.sh --no-install build only; files in desktop/dist/
#
# Needs the pinned Rust toolchain (rust/rust-toolchain.toml) and python3.
# Nothing is downloaded except the crates cargo fetches. On macOS the app is
# signed ad hoc (no certificate), as an unsigned release is. Runs in Git Bash
# on Windows.
#
# Differences from the release workflow, on purpose:
# - only this machine's architecture is built (no universal macOS binary,
#   and Linux uses the glibc target, so musl-tools is not needed);
# - each binary is built once, so the two-build byte compare is skipped;
# - without cargo-about the desktop notices file is a placeholder.
#
# WPANTRY_DESKTOP_HOME, when set, makes Setup install into that folder
# instead of the usual place (used by CI and tests).
#
# TODO: offer --universal on macOS when both Apple targets are installed.

set -euo pipefail

usage() {
  sed -n '3,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

install=yes
open=no
for arg in "$@"; do
  case "$arg" in
    --no-install) install=no ;;
    --open) open=yes ;;
    --help|-h) usage; exit 0 ;;
    *) echo "install-local.sh: unknown option $arg" >&2; usage >&2; exit 2 ;;
  esac
done
if [ "$install" = no ] && [ "$open" = yes ]; then
  echo "install-local.sh: --open and --no-install cannot be combined" >&2
  exit 2
fi

desktop="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
root="$(dirname "$desktop")"
build="$root/rust/release/build.sh"
dist="$desktop/dist"

# Python: python3, or python where only that exists (Windows).
python="${PYTHON:-}"
if [ -z "$python" ]; then
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null && "$candidate" -c 'import sys; assert sys.version_info >= (3, 11)' 2>/dev/null; then
      python="$candidate"
      break
    fi
  done
fi
[ -n "$python" ] || { echo "install-local.sh: needs Python 3.11 or newer (python3)" >&2; exit 1; }

# The pinned toolchain must already be installed: this script does not
# download toolchains.
toolchain="$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$root/rust/rust-toolchain.toml")"
if ! (cd "$root/rust" && rustup run "$toolchain" rustc --version >/dev/null 2>&1); then
  echo "install-local.sh: Rust $toolchain is not installed. Run this, then try again:" >&2
  echo "  cd \"$root/rust\" && rustup toolchain install" >&2
  exit 1
fi
cmp -s "$root/rust/rust-toolchain.toml" "$desktop/rust-toolchain.toml" ||
  { echo "install-local.sh: rust/ and desktop/ pin different toolchains" >&2; exit 1; }
host="$(cd "$root/rust" && rustc -vV | sed -n 's/^host: //p')"

exe=""
case "$host" in
  *-apple-darwin) package_target=universal-apple-darwin; setup_ext=.zip ;;
  *-pc-windows-msvc) package_target="$host"; exe=.exe; setup_ext=.exe ;;
  *-linux-gnu) package_target="$host"; setup_ext=.tar.gz ;;
  *) echo "install-local.sh: $host is not a platform Pantry Desktop supports" >&2; exit 1 ;;
esac

# build.sh stamps the build with the last commit's time; a source archive
# without Git history uses the current time instead.
if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  SOURCE_DATE_EPOCH="$(git -C "$root" log -1 --format=%ct 2>/dev/null || date +%s)"
  export SOURCE_DATE_EPOCH
fi

mkdir -p "$dist"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
# Git Bash: give Python and the Windows tools C:/... paths, which bash
# reads too, instead of relying on MSYS argument conversion.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    work="$(cygpath -m "$work")"
    desktop="$(cygpath -m "$desktop")"
    dist="$(cygpath -m "$dist")"
    ;;
esac

echo "==> Building the scanner for $host"
"$build" "$host" "$work/wpantry$exe"
echo "==> Building Pantry Desktop for $host"
"$build" "$host" "$work/wpantry-desktop$exe" wpantry-desktop

notices="$work/PANTRY-DESKTOP-NOTICES.txt"
if cargo about --version >/dev/null 2>&1; then
  echo "==> Writing licence notices with cargo-about"
  (cd "$desktop" && cargo about generate --locked --fail -c release/about.toml release/about.hbs) > "$notices"
else
  echo "==> cargo-about is not installed; writing a placeholder notices file"
  cat > "$notices" <<'EOF'
This copy of Pantry Desktop was built from source with
desktop/release/install-local.sh on a machine without cargo-about, so the
licence notices for the desktop app's Rust dependencies were not generated.

To generate them, install cargo-about 0.9.3 and build again:

    cargo install --locked cargo-about@0.9.3

The scanner's notices are in PANTRY-SCANNER-NOTICES.txt beside this file.
Release downloads always carry the full notices.
EOF
fi

desktop_zip="$dist/wpantry-desktop-$package_target.zip"
setup_out="$dist/wpantry-setup-$package_target$setup_ext"
echo "==> Packaging $desktop_zip"
"$python" "$desktop/release/package.py" "$package_target" "$work/wpantry-desktop$exe" "$work/wpantry$exe" "$notices" "$desktop_zip"
if [ "$package_target" = universal-apple-darwin ]; then
  echo "==> Signing Pantry.app ad hoc"
  "$python" "$desktop/release/sign.py" macos "$desktop_zip"
fi

echo "==> Building Pantry Setup"
"$python" "$desktop/release/setup.py" payload "$desktop_zip" "$work/setup-payload.zlib"
# Setup embeds its payload when it is compiled, except on macOS, where it
# reads the payload from its app bundle.
if [ "$package_target" != universal-apple-darwin ]; then
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) PANTRY_SETUP_PAYLOAD="$(cygpath -w "$work/setup-payload.zlib")" ;;
    *) PANTRY_SETUP_PAYLOAD="$work/setup-payload.zlib" ;;
  esac
  export PANTRY_SETUP_PAYLOAD
fi
"$build" "$host" "$work/wpantry-setup$exe" wpantry-setup
unset PANTRY_SETUP_PAYLOAD
"$python" "$desktop/release/setup.py" bundle "$package_target" "$work/wpantry-setup$exe" "$work/setup-payload.zlib" "$setup_out"
if [ "$package_target" = universal-apple-darwin ]; then
  echo "==> Signing Pantry Setup.app ad hoc"
  "$python" "$desktop/release/sign.py" macos "$setup_out"
fi

echo "Built:"
echo "  $desktop_zip"
echo "  $setup_out"
if [ "$install" = no ]; then
  exit 0
fi

# Run Setup from an unpacked copy, as a downloaded one would run.
case "$setup_ext" in
  .zip)
    ditto -x -k "$setup_out" "$work/setup"
    setup="$work/setup/Pantry Setup.app/Contents/MacOS/Pantry Setup"
    where="$HOME/Applications/Pantry/Pantry.app"
    ;;
  .tar.gz)
    mkdir -p "$work/setup"
    tar -xzf "$setup_out" -C "$work/setup"
    setup="$work/setup/Pantry Setup"
    where="${XDG_DATA_HOME:-$HOME/.local/share}/pantry-desktop"
    ;;
  .exe)
    setup="$setup_out"
    where="${LOCALAPPDATA:-%LOCALAPPDATA%}\\Programs\\Pantry"
    ;;
esac
if [ -n "${WPANTRY_DESKTOP_HOME:-}" ]; then
  where="$WPANTRY_DESKTOP_HOME/installed"
fi

if [ "$open" = yes ]; then
  echo "==> Installing and opening Pantry"
  "$setup"
else
  echo "==> Installing Pantry"
  "$setup" --install-only
fi
echo "Pantry is installed in $where"
