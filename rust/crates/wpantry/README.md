# wpantry

The library behind [Pantry](https://github.com/waffuruai/pantry): it inventories a computer and its git repositories, checks only what is installed or locked against OSV.dev, CISA KEV and endoflife.date, scans for malware and risky settings, and keeps the answers in a local SQLite cache. It never prints and keeps no global state; the `wpantry` binary ([`wpantry-cli`](https://crates.io/crates/wpantry-cli)) is its reference user.

```toml
[dependencies]
wpantry = { version = "=0.5.0" }
```

Start from `checks::Options` and `checks::Scan`, `db::Cache`, `finding::Finding` and `reporters`; the crate's front page on docs.rs has a worked example. The API is `0.x`, so pin it exactly. What stays stable across versions is the [CLI contract](https://github.com/waffuruai/pantry/blob/main/specs/cli-contract.md). Docs, install and usage: <https://github.com/waffuruai/pantry>.
