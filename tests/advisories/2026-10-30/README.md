# Advisory boundaries, 2026-10-30

Offline regression fixtures for the affected/fixed boundaries checked on 2026-10-30 (pantry issue #57). `tests/contract/test_advisories.py` replays them through the cache and runs `wpantry check --no-machine --offline --no-input --json` on the two synthetic checkouts here, so CI never asks OSV and the expectations cannot drift with the live records.

Nothing here is a real project: the lockfiles hold package names and versions only, and no package is installed or run.

## What is here

| Path | Holds |
|---|---|
| `osv/GHSA-*.json` | The eleven OSV records below, as `https://api.osv.dev/v1/vulns/<id>` returned them on 2026-10-31 (pretty-printed, keys sorted, otherwise unchanged). Each record carries its own `modified` stamp |
| `osv/WPANTRY-TEST-KEV-1.json` | **Synthetic.** A made-up crates.io `brotli` range (`< 8.0.2`) with the alias CVE-2026-111497, so one fixture finding carries a KEV CVE. The CVE is real and in the catalog; the range, the id and the summary are invented and say so. It is a check that the `kev` flag is set from the offline catalog, not a claim about brotli |
| `kev.json` | CISA's catalog trimmed to the one entry CVE-2026-111497 (Google Brotli Unchecked Return Value Vulnerability, added 2026-10-27), with the catalog's `title`, `catalogVersion` and `dateReleased`; source `https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json`, retrieved 2026-10-31 |
| `affected/` | `Cargo.lock`, `package-lock.json` (v3) and `requirements.txt` pinning the last affected version of every control. The requirements file spells `Authlib`, `Twisted` and `langgraph_sdk` as a person would, so the run proves the binary normalizes them (PEP 503) to the keys the cache holds |
| `fixed/` | The same files at the first fixed version |

## The controls

| Package | Ecosystem | Affected → fixed | Target family | Alias |
|---|---|---|---|---|
| zip | crates.io | 9.0.4 → 9.0.5 | [GHSA-m665-v7pm-7grj](https://github.com/advisories/GHSA-m665-v7pm-7grj) | CVE-2026-115905 |
| zip | crates.io | 8.6.0 → 9.0.0 | [GHSA-hjqx-j4rw-g7xv](https://github.com/advisories/GHSA-hjqx-j4rw-g7xv) | CVE-2026-115908 |
| wasmtime | crates.io | 48.0.6 → 48.0.7 | [GHSA-mghf-wjfp-p5xm](https://github.com/advisories/GHSA-mghf-wjfp-p5xm) | CVE-2026-115893, RUSTSEC-2026-0379 |
| mlflow | PyPI | 3.16.0 → 3.17.0 | [GHSA-26p8-2jq9-3vq9](https://github.com/advisories/GHSA-26p8-2jq9-3vq9) | CVE-2026-116692 |
| better-auth | npm | 1.7.6 → 1.7.7 | [GHSA-965c-763c-88jm](https://github.com/advisories/GHSA-965c-763c-88jm) | CVE-2026-110862, CVE-2026-114607 |
| Authlib | PyPI | 1.8.0 → 1.9.0 | [GHSA-6v38-4h7w-rj9h](https://github.com/advisories/GHSA-6v38-4h7w-rj9h) | CVE-2026-96760 |
| @sylphx/pdf-reader-mcp | npm | 3.0.0 → 3.0.1 | [GHSA-q344-5v34-gm84](https://github.com/advisories/GHSA-q344-5v34-gm84) | CVE-2026-62264 |
| Twisted | PyPI | 26.4.0 → 26.10.0rc1 | [GHSA-vpp8-g58w-m8mp](https://github.com/advisories/GHSA-vpp8-g58w-m8mp) | none |
| vite | npm | 6.4.4 → 6.4.5 | [GHSA-8g5g-mxqh-grgj](https://github.com/advisories/GHSA-8g5g-mxqh-grgj) | CVE-2026-118662 |
| decode-uri-component | npm | 0.5.0 → 0.5.1 | [GHSA-qr28-fpjm-wq7f](https://github.com/advisories/GHSA-qr28-fpjm-wq7f) | CVE-2026-118664 |
| langgraph-sdk | PyPI | 0.4.5 → 0.4.6 | [GHSA-3fx2-cqw9-xr3c](https://github.com/advisories/GHSA-3fx2-cqw9-xr3c) | CVE-2026-118667 |
| brotli (synthetic) | crates.io | 8.0.1 → 8.0.2 | `WPANTRY-TEST-KEV-1` (invented) | CVE-2026-111497 (KEV) |

Distinctions the suite keeps on purpose:

- **zip 9.0.0** clears GHSA-hjqx-j4rw-g7xv and is still in GHSA-m665-v7pm-7grj's range (fixed 9.0.5): a negative control for one family is never a clean verdict on the version. zip 8.6.0 is in both families and gets two findings, one fix each.
- **wasmtime** has branch-specific fixes (36.0.19, 48.0.7, 49.0.4); 48.0.6's fix is 48.0.7, the one on its own release line, not the highest.
- **Twisted**'s only fix is the prerelease 26.10.0rc1; it is reported as the fix.
- Findings show the CVE alias where there is one (Twisted's record has none, so its GHSA shows); the alias test re-stores vite's record under its CVE id and expects the finding under it, so a CVE-form row cannot evade an assertion keyed by GHSA.
- The PyPI cache keys are PEP 503 names (`authlib`, `twisted`, `langgraph-sdk`), whatever the requirements file spells.

## How the cache is seeded

The test runs the binary once to create the schema, then inserts each record into `vulns` and one `queries` row per (ecosystem, package, version) control with a fresh `checked_at` and the ids whose own ranges include that version (the affected controls), or none (the fixed ones), plus the KEV row. That is what OSV answered; the binary still does its own version comparison, fix selection, alias grouping and KEV marking.

## Record of verification

- Fixtures retrieved and the suite written on 2026-10-31 against `dev` at `7df75c6` (v0.2.0); 6 test methods, 22 affected/fixed control assertions plus the alias, normalization, export and KEV checks; all pass offline.
- The issue's earlier run: all 22 controls matched through the CLI at `70cdc9c36cbc6f74b50622a4d19f4f17f7e07d78` with live OSV answers (2026-10-30).
- A run of this suite says these boundaries still hold for these records. It says nothing about CVE coverage in general, and a fixed control that passes is not a clean verdict on that version.
