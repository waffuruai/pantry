# wpantry-cli

The `wpantry` binary: Pantry's command line, built on the [`wpantry`](https://crates.io/crates/wpantry) library and [`wcli`](https://crates.io/crates/wcli).

```bash
cargo install --locked wpantry-cli
wpantry scan
```

Verified release binaries, the install script and mise's `packslip:` install are in the [install guide](https://github.com/waffuruai/pantry/blob/main/docs/public/install.md); every command is in the [usage guide](https://github.com/waffuruai/pantry/blob/main/docs/public/usage.md). The command line is a [contract](https://github.com/waffuruai/pantry/blob/main/specs/cli-contract.md): exit codes, JSON shape and cache schema stay stable across versions. `wpantry licenses` prints the third-party notices built into the binary (`THIRD-PARTY-NOTICES.txt` in this crate).
