# Contributing

Contributions are welcome under the [MIT](LICENSE) license.

Start with the [README](README.md) for what wpantry is, [specs/cli-contract.md](specs/cli-contract.md) for the surface every change must keep, and [specs/](specs/README.md) for what is planned. We write issues, PRDs and pull requests by the rules in [waffuruai/ops `.agents`](https://github.com/waffuruai/ops/tree/dev/.agents): open an issue first, keep a PR to one change, and say in its description which spec it updated or "no PRD impact".

Tooling comes from [mise](https://mise.jdx.dev). Set up and test with:

```bash
mise bootstrap
mise run test
```

`mise bootstrap` installs the pinned Python (for the contract suite), gitleaks, shellcheck and actionlint from [`mise.toml`](mise.toml), builds wpantry on the toolchain `rust/rust-toolchain.toml` pins (rustup installs it) and runs `wpantry tools` to confirm them. `mise run test` runs the Rust tests, the CA trust test and the install.sh test; `mise tasks ls` lists the rest (`build`, `contract`, `lint`, `check`). CI runs the same tasks from the same file, so bumping a pin there bumps it everywhere, and one job runs the shell tests inside ops' bootstrap container (`containers/Dockerfile.bootstrap` at the ops commit `OPS_REF` in `.github/workflows/ci.yml`). Without mise, install gitleaks yourself; `wpantry tools` says what is missing. Before opening a pull request, run `mise run test` and `mise run lint`, and `mise run contract` when the change touches the CLI. Rust changes also run `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings` and `cargo test --locked` in `rust/`, under the dependency rules in [rust/README.md](rust/README.md).

A change to the CLI, the JSON output, the exit codes or the cache schema updates [specs/cli-contract.md](specs/cli-contract.md) in the same PR and follows its change rule: additive only, or bump `schema`. A new check needs a test that runs offline.

Keep examples and fixtures generic. Do not commit secrets, tokens, real email addresses, usernames, machine identifiers, personal paths or captured scan output. A finding from your own machine is reported as a minimal reproducer, never as a pasted report.

Security reports do not go in a pull request or a public issue. Follow [SECURITY.md](SECURITY.md).
