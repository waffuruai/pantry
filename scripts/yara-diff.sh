#!/usr/bin/env bash
# Compare wpantry-yara with the reference yara on a corpus: both scan it with
# the same rules inside one throwaway container (offline, read-only, non-root),
# and any rule/file pair only one of them reports is printed. Exit 1 on a
# difference. The corpus never leaves the container it is mounted in.
#
#   scripts/yara-diff.sh RULES.yar CORPUS
#
# CORPUS is a directory, or `volume:NAME` for a Docker volume (a quarantine
# volume, say, whose files stay inside Docker). Needs docker and the
# aarch64/x86_64 musl Rust target for this machine's Docker architecture.
set -euo pipefail

rules=${1:?usage: yara-diff.sh RULES.yar CORPUS}
corpus=${2:?usage: yara-diff.sh RULES.yar CORPUS}
root="$(cd "$(dirname "$0")/.." && pwd)"
image="pantry-yara-diff:local"
yara_version="4.5.7"

arch="$(docker info --format '{{.Architecture}}')"
case "$arch" in
  aarch64|arm64) target=aarch64-unknown-linux-musl ;;
  x86_64|amd64) target=x86_64-unknown-linux-musl ;;
  *) echo "unsupported docker architecture: $arch" >&2; exit 2 ;;
esac

# The engine's checker, static, for the container.
(cd "$root/rust" && env -u RUSTUP_TOOLCHAIN rustup target add "$target" >/dev/null &&
  env -u RUSTUP_TOOLCHAIN RUSTFLAGS="-C linker=rust-lld -C target-feature=+crt-static" \
    cargo build --locked --release --example yara_check --target "$target" >/dev/null)
checker="$root/rust/target/$target/release/examples/yara_check"

# The reference: Alpine's yara, pinned by version.
docker build -q -t "$image" - >/dev/null <<EOF
FROM alpine:3.24.3
RUN apk add --no-cache "yara=~${yara_version}" coreutils && adduser -D -H -u 10001 q
USER q
EOF

if [[ "$corpus" == volume:* ]]; then
  mount="type=volume,src=${corpus#volume:},dst=/corpus,readonly"
else
  mount="type=bind,src=$(cd "$corpus" && pwd),dst=/corpus,readonly"
fi

docker run --rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=256m --memory 2g --pids-limit 64 \
  --mount "$mount" \
  --mount "type=bind,src=$(cd "$(dirname "$rules")" && pwd)/$(basename "$rules"),dst=/rules.yar,readonly" \
  --mount "type=bind,src=$checker,dst=/yara_check,readonly" \
  "$image" sh -c '
    set -e
    start=$(date +%s)
    yara -r -w /rules.yar /corpus 2>/dev/null | sed "s|/corpus//|/corpus/|" | sort > /tmp/yara.txt
    mid=$(date +%s)
    /yara_check /rules.yar /corpus 2>/tmp/ours.err | sort > /tmp/ours.txt
    end=$(date +%s)
    grep -E "^compiled|^scanned" /tmp/ours.err >&2
    echo "yara: $(wc -l < /tmp/yara.txt) matches in $((mid - start))s; wpantry-yara: $(wc -l < /tmp/ours.txt) in $((end - mid))s" >&2
    diff=0
    if comm -23 /tmp/yara.txt /tmp/ours.txt | grep -q .; then echo "only yara:"; comm -23 /tmp/yara.txt /tmp/ours.txt; diff=1; fi
    if comm -13 /tmp/yara.txt /tmp/ours.txt | grep -q .; then echo "only wpantry-yara:"; comm -13 /tmp/yara.txt /tmp/ours.txt; diff=1; fi
    exit $diff
  '
