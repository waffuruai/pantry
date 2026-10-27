# Publishing to crates.io

How the crates get onto crates.io: by hand once, for the first release, and through the release workflow after that. The rest of a release (tags, binaries, signatures) is the [release playbook](release.md).

Today the crates are `wscanner` (library) and `wscanner-cli` (the binary). If the project ships as **pantry**, publish as `wpantry` and `wpantry-cli`: `pantry` is taken on crates.io (an unrelated crate from 2020), and our crates take the `w` prefix. Decide before the first publish, because a crate name can't be changed or released once published.

## The first publish (by hand, once)

1. **Account.** Sign in to [crates.io](https://crates.io) with GitHub, and verify your email under Account Settings: crates.io refuses to publish without a verified email.
2. **Names.** Check each name is free: `https://crates.io/crates/<name>` returns "not found". The first publish claims a name for good.
3. **Metadata.** In `rust/Cargo.toml` and each crate's `Cargo.toml`, check `description`, `license`, `repository`, `readme`, `keywords` (at most 5), `categories` and `rust-version`. crates.io rejects a crate without `description` and `license`.
4. **Contents.** List what each crate would upload: `cd rust && cargo package --list -p wscanner` (then `-p wscanner-cli`). Nothing private should be listed (fixtures with real paths, `.env`, scan output); fix `include`/`exclude` if it is.
5. **Token.** crates.io → Account Settings → API Tokens → New Token: scopes `publish-new` and `publish-update`, crate pattern `wscanner*` (or `wpantry*`), expiry 1 day.
6. **Log in.** `cargo login` and paste the token (cargo stores it in `~/.cargo/credentials.toml`).
7. **Dry run.** `cargo publish --dry-run --locked -p wscanner`: it builds the crate from its packaged sources, exactly as crates.io would.
8. **Publish, library first.** From the release tag (`git switch --detach vX.Y.Z`): `cargo publish --locked -p wscanner`, then `cargo publish --locked -p wscanner-cli`. The CLI depends on the library, so the library must be on crates.io first; cargo waits for it to appear.
9. **Check.** Both crates show the version on crates.io, docs.rs builds the library's docs within a few minutes, and `cargo install --locked wscanner-cli@X.Y.Z` works in a clean `rust` container.
10. **Revoke.** Delete the token on crates.io, then `cargo logout`.
11. **Co-owners.** `cargo owner --add github:waffuruai:owners wscanner wscanner-cli`, so the crates don't depend on one person's account. The waffuruai org has to allow the crates.io GitHub app first (org settings → Third-party access).
12. **Trusted publishing.** For each crate: crates.io → the crate → Settings → Trusted Publishing → add repository `waffuruai/wscanner`, workflow `release.yml`, environment `release`. Then set the repository variable `CRATES_IO_TRUSTED_PUBLISHING` to `true`.

## Every release after that

Nothing by hand: the release workflow's last step publishes both crates with a short-lived token from GitHub's OIDC identity (trusted publishing), after the `release` environment is approved. No token is stored anywhere.

## Good to know

- **Publishing is permanent.** A version can't be deleted or overwritten. A bad one is yanked (`cargo yank --version X.Y.Z wscanner-cli`, then `wscanner`): existing lockfiles keep working, new ones won't pick it. Then publish the next patch.
- **Versions** come from `[workspace.package]` in `rust/Cargo.toml`, and the CLI pins the library at exactly that version. See [Versions](release.md#versions).
- **A secret published by mistake** is public forever, even after a yank: rotate it at once.
