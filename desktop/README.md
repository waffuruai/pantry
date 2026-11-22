# Pantry Desktop

A native window (egui) over the `wpantry` scanner for macOS, Linux and Windows: it shows what needs attention, fixes what it can after one confirm, then scans again to check. It reads the same results, history and schedule as the CLI. User guide: [docs/public/desktop.md](../docs/public/desktop.md). Install, update and removal: [install.md](../docs/public/install.md#download-pantry-setup).

The crate builds two binaries: `wpantry-desktop` (the app) and `wpantry-setup` (Pantry Setup, the per-user installer). `release/` holds `wpantry-release`, the packager and signer the release workflow runs.

## Build and run

Use the pinned toolchain (`rust-toolchain.toml`, the same as `rust/`). In Git Bash on Windows, add `.exe` to the binary names.

```sh
(cd rust && cargo build --locked -p wpantry-cli)
(cd desktop && cargo build --locked)
desktop/target/debug/wpantry-desktop --scanner rust/target/debug/wpantry
```

The app uses `--scanner`, else the scanner beside its executable (inside `Pantry.app/Contents/MacOS` on macOS). Debug builds also try PATH; release builds never do.

## Test

```sh
(cd desktop && cargo test --locked)
(cd desktop/release && cargo test --locked)
(cd desktop && xvfb-run -a cargo test --locked --test native_smoke -- --ignored)
```

`cargo test` includes the end-to-end suite (`tests/e2e`): headless, on all three systems, against the built scanner (`PANTRY_E2E_SCANNER`, default `rust/target/debug/wpantry`) and the `wpantry-standin` stand-ins, which never ship. Its ignored tests `bundle`, `setup` and `screens` check a built download (`PANTRY_E2E_BUNDLE=ZIP cargo test --test e2e -- --ignored --exact bundle`; likewise `PANTRY_E2E_SETUP`, `PANTRY_E2E_SCREENS`). The smoke test opens a real window under Xvfb on Linux.

Headless driving uses `--automation`: one JSON object per line on stdin, one `{"ok": ..., "result"|"error": ...}` per line on stdout. Ops: `wait`, `tree`, `click`, `set_value`, `key`, `scroll_into_view`, `resize`, `screenshot`, `state`, `cancel`, `set_time_limit` and `dispatch` (the typed action dispatcher in `src/app`). Every interactive control has an AccessKit author ID, and the suite fails on a missing or duplicate one.

```jsonl
{"op":"click","id":"nav.results"}
{"op":"dispatch","command":{"action":"scan","path":"/path/to/project","offline":true}}
```

## Package

`release/install-local.sh` builds release binaries, packages them as a release does and installs them with Setup (`--open`, `--no-install`, `--help`; `WPANTRY_DESKTOP_HOME` redirects the install). The release workflow runs the packager directly:

```sh
wpantry-release package TARGET APP SCANNER NOTICES OUT.zip
wpantry-release setup payload OUT.zip setup-payload.zlib
wpantry-release setup bundle TARGET SETUP setup-payload.zlib OUT
wpantry-release sign macos ZIP | sign windows FILE --thumbprint SHA1
```

Archives are deterministic (sorted names, fixed modes, no timestamps), so two builds of one commit match byte for byte. Signing is in [docs/internal/release.md](../docs/internal/release.md#code-signing).
