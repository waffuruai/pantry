# Contributing

Thanks for your interest. Pantry is a small, focused project; these rules keep contributions coherent and the maintainer queue sane. Contributions are welcome under the [MIT](LICENSE) license.

**TL;DR:**
- Open an issue **before** opening a PR, with the [issue template](.github/ISSUE_TEMPLATE/issue.yml).
- PRs without a linked, discussed issue **will be closed**.
- One logical change per PR, written up in the [PR template](.github/PULL_REQUEST_TEMPLATE.md). Tests and docs land with the code that needs them.
- AI-assisted contributions are welcome; disclose how you used AI in the issue and PR templates.

Start with the [README](README.md) for what Pantry is, [docs/public/architecture.md](docs/public/architecture.md) for how it works, [docs/public/checks-and-sources.md](docs/public/checks-and-sources.md) for what it checks and asks, [specs/cli-contract.md](specs/cli-contract.md) for the surface every change must keep, and [specs/](specs/README.md) for what is planned.

## Open an issue first

Even for small changes. The issue is where we agree on scope, surface related work and pick an approach; five minutes there saves a rewrite on the PR. Search [existing issues](https://github.com/waffuruai/pantry/issues?q=is%3Aissue) and [specs/](specs/README.md) first; it may already be planned or fixed on `dev`.

Use the [issue template](.github/ISSUE_TEMPLATE/issue.yml): tick the type (bug, feature, coverage, performance, discussion), give a minimal reproducer or the proposal, name the spec section and criteria it serves, and tick the AI-assistance boxes. Blank issues are turned off so every issue carries that metadata. A vulnerability in Pantry itself does not go in an issue: follow [SECURITY.md](SECURITY.md).

## What a good PR looks like

- **Linked to an open, discussed issue** (`Fixes #123`, or `Refs #123` for partial work). PRs without one are closed, maintainers included.
- **Scoped tightly.** One logical change per PR. If it touches three unrelated things, that is three PRs.
- **Uses the [PR template](.github/PULL_REQUEST_TEMPLATE.md)**: a one-paragraph summary a reviewer can read in thirty seconds, what changed grouped by file or subsystem, how it was verified, the documentation it updated (the README, [specs/cli-contract.md](specs/cli-contract.md) when the CLI, JSON, exit codes or cache schema change, and the PRD in `specs/` it affects, or "no PRD impact"), and the AI-assistance disclosure.
- **Conventional-commit title** (`feat:`, `fix:`, `perf:`, `docs:`, `test:`, `chore:`, `refactor:`, with `!` for a breaking change); `.github/release.yml` sorts the release notes by it.
- **Tests for behaviour changes, docs for user-visible ones**, in the same PR. A new check needs a test that runs offline. "Tests in a follow-up" is not accepted.
- **Green CI** before requesting review.

AI-assisted PRs should read no differently from hand-written ones: tight description, linked issue, scoped diff, tests, docs. Don't paste raw assistant output; if the diff sprawls or the description rambles, tighten it first. The same goes for issues.

## Commit authorship

Every commit is authored by the human GitHub account that is accountable for it, and that account is the author on record when it merges. A tool you used is not a co-author.

- **No AI or agent attribution** in commits, PR titles or PR bodies: no `Co-authored-by`, `Signed-off-by`, `Assisted-by` or other trailer naming Claude, Codex, ChatGPT, Copilot, Cursor, Gemini, Grok, Devin, Aider, Windsurf or any other tool or bot; no "Generated with …" or 🤖 footer; no commit authored or committed by a tool's or bot's identity. Trailers naming people are fine.
- **Disclose AI use in the PR template's AI assistance section**, and nowhere else.
- **Set your agent up so it complies** before it commits: turn off its attribution (Claude Code: `"attribution": {"commit": "", "pr": ""}` in `settings.json`; Aider: `--no-attribute-co-authored-by --no-attribute-author --no-attribute-committer`; others have a similar setting), and let it commit as your git identity, not its own. Org members get a `commit-msg` hook that rejects these lines from ops' `mise run hooks`. Anyone can check a branch before pushing with `python3 scripts/commit_hygiene.py --range origin/dev..HEAD`.
- **To fix a branch that already has them:** `git rebase -i origin/dev`, `reword` each listed commit to drop the line (`git commit --amend --reset-author --no-edit` for one a tool authored), then `git push --force-with-lease`. For the PR title or body, edit the PR.

The `Commit hygiene` CI check enforces this on every pull request, over each commit's author, committer and message and the PR title and body, and a PR that fails it is not merged. Maintainers squash-merge, and the squash commit carries the PR's title and body and every commit message in the PR, with their trailers; that is why each commit is checked, not only the PR text.

## Setup and checks

Tooling comes from [mise](https://mise.jdx.dev). Set up and test with:

```bash
mise bootstrap
mise run test
```

- `mise bootstrap` installs the pinned tools from [`mise.toml`](mise.toml) (Python for `scripts/`, shellcheck, actionlint, cargo-llvm-cov, cargo-about), builds `wpantry` on the toolchain `rust/rust-toolchain.toml` pins, and runs `wpantry tools` to confirm them.
- `mise run test` runs every test offline; `mise tasks ls` lists the rest (`build`, `contract`, `coverage`, `lint`, `notices`, `vet`).
- CI runs the same tasks from the same file, so a pin bumped there is bumped everywhere.
- Before a pull request: `mise run test` and `mise run lint`; `mise run contract` when the change touches the CLI; `mise run vet` and `mise run notices` when it bumps a dependency, `mise run vet` when it bumps an action ([dependencies](docs/internal/dependencies.md)). In `rust/`: `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked`.

**Coverage.** `mise run coverage` measures line coverage of every Rust test in one instrumented build ([cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov)) and fails under 90%; `--html` also writes the per-line report to `rust/target/llvm-cov/html`. Nothing is excluded: code that shells out to the real machine is covered through recorded output where possible and counts as uncovered where not. A change that adds code adds its tests in the same PR; the fix for a drop is tests, not an exclusion.

A change to the CLI, the JSON output, the exit codes or the cache schema updates [specs/cli-contract.md](specs/cli-contract.md) in the same PR and follows its change rule: additive only, or bump `schema`.

Keep examples and fixtures generic. Do not commit secrets, tokens, real email addresses, usernames, machine identifiers, personal paths or captured scan output. The exceptions are under `rust/supply-chain/`: `imports.lock` copies other projects' published `cargo vet` audits with the auditor identities those projects publish, and `audits.toml` records ours under the team identity `Waffuru AI, Inc. <security@waffuru.ai>` (the commit says who did the work). A finding from your own machine is reported as a minimal reproducer, never as a pasted report.

Security reports do not go in a pull request or a public issue. Follow [SECURITY.md](SECURITY.md).
