# Pantry

Waffuru's security vulnerability scanner, built on the OSV database and other CVE sources. Its command is `wpantry`.

Pantry finds the vulnerabilities that actually apply to your computer. It inventories what is installed and what your git repos lock, asks [OSV.dev](https://osv.dev), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) and [endoflife.date](https://endoflife.date) only about those exact versions, and fails only when something here has a known vulnerability with a released fix, is past end of life, is a known malicious package, or is a committed secret. Answers live in a local SQLite cache, so a second run the same day takes seconds. Nothing that isn't installed is reported, and a source it can't reach is reported "not checked", never clean.

| What you get | What it checks |
|---|---|
| Know which installed things need updating, and the exact safe version | Runtimes and compilers (every version managers keep, not just PATH), package managers, CLI tools, datastores, Docker, global pip/npm/gem/cargo/pipx packages, Homebrew formulae (`brew vulns`); mise itself against OSV and its latest release (behind warns; `--update` never updates it) |
| Catch vulnerable dependencies before they ship | Lockfiles in every git repo: Cargo, npm, pnpm, yarn, bun, deno, Swift, Go, uv, poetry, pip, Bundler, Composer, Maven, Gradle, NuGet and more |
| Catch malware, not just CVEs | Every package name against the OpenSSF malicious-packages index; VS Code's malicious-extension list |
| Find leaked credentials in history | Secrets committed anywhere in each repo's git history (`gitleaks`) |
| See what your AI coding tools actually run | Claude Code, Codex, Cursor, Gemini CLI and other harnesses: their MCP servers (unpinned ones warn), plugins, skills and bundled npm packages |
| Keep the OS, browsers and apps current | macOS Software Update, Debian/Ubuntu/Alpine/openSUSE packages, dnf distros, Arch; Chrome, Firefox; Electron apps; other apps against the Homebrew cask catalog |
| Know when a runtime stops getting fixes | End-of-life dates for runtimes and datastores |
| Know whether the machine itself is set up safely | FileVault or LUKS, the firewall, Gatekeeper and SIP, automatic updates, Remote Login and the sharing services, guest and automatic login, the screen lock (CIS benchmark items, read-only; `--no-posture` skips them) |
| Spot a compromised certificate authority | System, OpenSSL, Homebrew, certifi, pip and Node trust stores against the leaked eMudhra CAs (`ca-trust/fix-ca-trust.sh` distrusts them) |
| Review supply-chain risk | Dependency licenses outside an allowlist, npm install scripts, container images your repos build from |
| Fix it, safely | `--update` runs only unattended, user-level fixes; everything needing sudo or a code change is printed as a step |

Every check, every source it asks and exactly what is sent to each: [docs/public/checks.md](docs/public/checks.md).

## Install

```bash
mise use -g packslip:github.com/waffuruai/pantry                                 # with mise (the default)
curl -fsSL https://github.com/waffuruai/pantry/releases/latest/download/install.sh | sh  # without mise
```

Both verify the release before installing: mise against the release's signed packslip, and `install.sh` against `SHA256SUMS` and a signature (packslip, `gh` or `cosign`, whichever you have). [docs/public/install.md](docs/public/install.md) has the details, manual verification, crates.io and building from source. Releases cover macOS (one binary for Apple silicon and Intel) and Linux (x86-64 and arm64, static); Windows: [#11](https://github.com/waffuruai/pantry/issues/11). Homebrew: [#10](https://github.com/waffuruai/pantry/issues/10).

`wpantry tools` lists the external tools it uses (`git`, `gitleaks`, `openssl`; `brew` and `docker` when present) and which are missing.

## Usage

```bash
wpantry                                       # this computer: machine + every git repo under ~
wpantry --path ~/code/myproject --no-machine  # one project, no machine inventory
wpantry check --json --no-input               # findings for tools and agents
wpantry search "tarfile" --applicable         # ranked search of cached advisories
wpantry export --csv findings.csv             # id, url, component, affected and safe version
wpantry --update --dryrun                     # the update plan, change nothing
wpantry --update                              # apply the unattended fixes, then re-check
```

Exit codes: 0 clean (warnings included), 1 something fails, 2 usage error, 3 internal error.

**Scope.** By default wpantry checks the machine and every git repo it finds under your home directory, with a bounded walk (depth 6, no symlinks, skipping `Library`, caches, toolchains, `node_modules` and app bundles; it prints how many repos it found). `--path DIR` (repeatable) limits the repo checks to those directories; `--no-machine` skips the machine inventory. Policy files default to the bundled ones in [`rust/crates/wpantry/assets/defaults/`](rust/crates/wpantry/assets/defaults/) and can be replaced with `--gitleaks-config` and `--install-scripts`. Dependency licenses are not checked unless you pass `--licenses` (the bundled allowlist) or `--licenses FILE`; `--license` works too.

**Cache.** `~/.cache/wpantry/wpantry.db` (or `$XDG_CACHE_HOME/wpantry/`, or `WPANTRY_DB`). It holds only OSV records for what is here, which versions were checked and when, the latest findings and the side feeds; never a mirror of OSV.

**What leaves the machine.** Package names and versions go to OSV.dev; feeds are fetched. The optional email breach check sends your address to Have I Been Pwned (`HIBP_API_KEY`) or XposedOrNot, and only after you say yes. Source by source: [docs/public/checks.md](docs/public/checks.md#sources).

**Agents.** `wpantry skill` prints the agent skill ([rust/crates/wpantry/assets/SKILL.md](rust/crates/wpantry/assets/SKILL.md)).

**Output.** On a terminal the report is coloured (failures red, warnings yellow, what's fine green) and questions are `y/n` prompts; `NO_COLOR` turns colour off, and pipes, files and `--json` never get it.

## Docs

- [Install and verify a release](docs/public/install.md), [use wpantry](docs/public/usage.md), [what it checks and its sources](docs/public/checks.md), and [the machine's settings it checks](docs/public/posture.md).
- For maintainers: the [release playbook](docs/internal/release.md), [publishing to crates.io](docs/internal/crates-io.md) and [dependency rules](docs/internal/dependencies.md).

## Development

```bash
mise bootstrap   # the pinned tools, then build wpantry and run `wpantry tools` to confirm them
mise run test    # the Rust tests, the CA trust test and the install.sh test, offline
```

`mise tasks ls` lists the rest: `mise run build`, `mise run test rust`, `mise run test ca-trust`, `mise run test install`, `mise run lint`, `mise run contract` (the CLI contract suite against `WPANTRY`, default the binary `build` makes), and `mise run check` (`wpantry check` with the pinned tools; flags after `--`). The code is in `rust/` ([rust/README.md](rust/README.md)); the standalone CA trust check and fix are in `ca-trust/`.

The CLI contract wpantry keeps is [specs/cli-contract.md](specs/cli-contract.md); all specs are indexed in [specs/](specs/README.md). See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## Acknowledgements

Pantry stands on open source code and open data. The code we read and wrote against:

- [osv-scanner](https://github.com/google/osv-scanner) and [osv-scalibr](https://github.com/google/osv-scalibr) (Google, Apache-2.0): how lockfiles and Linux package databases map to OSV ecosystems. wpantry's readers were written against their test fixtures, and the Python implementation ran osv-scanner itself before the Rust port.
- [Mergen](https://github.com/sametsazak/mergen) (MIT): which macOS security settings an unprivileged process can read and fix, behind the posture checks.
- [gitleaks](https://github.com/gitleaks/gitleaks) (MIT): the secret scan, run as an external tool with our bundled rules.

The data it asks, each under its publisher's terms:

- [OSV.dev](https://osv.dev) and the [OSV schema](https://ossf.github.io/osv-schema/) (Google and the OpenSSF): the vulnerability database behind every package question, aggregating the GitHub Advisory Database, RustSec, PyPA, the Go vulnerability database and the distributions' own trackers.
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): the `KEV` mark.
- [endoflife.date](https://endoflife.date) (MIT): end-of-life dates.
- [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) (Apache-2.0): known malicious package names.
- [deps.dev](https://deps.dev), the [Homebrew](https://brew.sh) formulae API and `brew vulns`, the [Arch Linux security tracker](https://security.archlinux.org), the Chrome and Firefox release feeds, the PostgreSQL security page, the VS Code Marketplace and [Open VSX](https://open-vsx.org), [Have I Been Pwned](https://haveibeenpwned.com) and [XposedOrNot](https://xposedornot.com).
- The [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) for macOS and Linux, which the posture checks follow, and the [eMudhra advisory](https://emudhra.we-have-a-problem.com/), which the certificate-authority check follows.

And the Rust crates it is built from, pinned in [rust/Cargo.toml](rust/Cargo.toml) under their own permissive licenses: serde and serde_json, rusqlite (SQLite), ureq and rustls.

## License

[MIT](LICENSE).
