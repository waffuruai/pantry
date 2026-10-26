# wscanner
Waffuru security vulnerability scanner using OSV database and other CVE sources.

wscanner finds the vulnerabilities that actually apply to your computer. It inventories what is installed and what your git repos lock, asks OSV.dev, CISA KEV and endoflife.date only about those exact versions, and fails only when something here has a known vulnerability with a released fix, is past end of life, is a known malicious package, or is a committed secret. Answers live in a local SQLite cache, so a second run the same day takes seconds. Nothing that isn't installed is reported, and a source it can't reach is reported "not checked", never clean.

| What you get | What it checks |
|---|---|
| Know which installed things need updating, and the exact safe version | Runtimes and compilers (every version managers keep, not just PATH), package managers, CLI tools, datastores, Docker, global pip/npm/gem/cargo/pipx packages, Homebrew formulae (`brew vulns`) |
| Catch vulnerable dependencies before they ship | Lockfiles in every git repo: Cargo, npm, pnpm, yarn, bun, deno, Swift, Go, uv, poetry, pip, Bundler, Composer and more (`osv-scanner`) |
| Catch malware, not just CVEs | Every package name against the OpenSSF malicious-packages index; VS Code's malicious-extension list |
| Find leaked credentials in history | Secrets committed anywhere in each repo's git history (`gitleaks`) |
| See what your AI coding tools actually run | Claude Code, Codex, Cursor, Gemini CLI and other harnesses: their MCP servers (unpinned ones warn), plugins, skills and bundled npm packages |
| Keep the OS, browsers and apps current | macOS Software Update, Debian/Ubuntu/Alpine/openSUSE packages, dnf distros, Arch; Chrome, Firefox; Electron apps; other apps against the Homebrew cask catalog |
| Know when a runtime stops getting fixes | End-of-life dates for runtimes and datastores |
| Spot a compromised certificate authority | System, OpenSSL, Homebrew, certifi, pip and Node trust stores against `python/distrusted-ca/` |
| Review supply-chain risk | Dependency licenses outside an allowlist, npm install scripts, container images your repos build from |
| Fix it, safely | `--update` runs only unattended, user-level fixes; everything needing sudo or a code change is printed as a step |

## Install

Python 3.9+ (standard library only) today:

```bash
git clone https://github.com/waffuruai/wscanner.git
wscanner/python/bin/wscanner tools      # which external tools it found
```

`osv-scanner` and `gitleaks` are required for the repo checks: `mise install` in the checkout pins both ([`mise.toml`](mise.toml)), or `brew install osv-scanner gitleaks`; `brew` and `docker` are used when present. A Rust binary is coming: see [specs/01-rust-port.md](specs/01-rust-port.md).

## Usage

```bash
wscanner                                       # this computer: machine + every git repo under ~
wscanner --path ~/code/myproject --no-machine  # one project, no machine inventory
wscanner check --json --no-input               # findings for tools and agents
wscanner search "tarfile" --applicable         # ranked search of cached advisories
wscanner export --csv findings.csv             # id, url, component, affected and safe version
wscanner --update --dryrun                     # the update plan, change nothing
wscanner --update                              # apply the unattended fixes, then re-check
```

(`wscanner` is `python/bin/wscanner`.) Exit codes: 0 clean (warnings included), 1 something fails, 2 usage error, 3 internal error.

**Scope.** By default wscanner checks the machine and every git repo it finds under your home directory, with a bounded walk (depth 6, no symlinks, skipping `Library`, caches, toolchains, `node_modules` and app bundles; it prints how many repos it found). `--path DIR` (repeatable) limits the repo checks to those directories; `--no-machine` skips the machine inventory. Policy files default to the bundled ones in `python/wscanner/defaults/` and can be replaced with `--gitleaks-config`, `--licenses` and `--install-scripts`.

**Cache.** `~/.cache/wscanner/wscanner.db` (or `$XDG_CACHE_HOME/wscanner/`, or `WSCANNER_DB`). It holds only OSV records for what is here, which versions were checked and when, the latest findings and the side feeds; never a mirror of OSV.

**What leaves the machine.** Package names and versions go to OSV; feeds are fetched. The optional email breach check sends your address to Have I Been Pwned (`HIBP_API_KEY`) or XposedOrNot, and only after you say yes.

**Agents.** `wscanner skill` prints the agent skill ([python/skill/wscanner/SKILL.md](python/skill/wscanner/SKILL.md)).

## Who uses it

- **ops**: `make secure` runs it on every Waffuru machine at install and in `make doctor`, with the org's policy files.
- **wsentinel**: the scan engine behind Sentinel's inventory, advisory and secret findings.
- **wci**: checks every pull request for security issues before it runs; **wrunner** and wci vet workloads before they run on someone else's machine (planned).
- **wOS** and wOS Server: baked into the OS image as a system service (planned). The same binary runs on its own on macOS, Linux and Windows.

## Development

```bash
python3 -m unittest discover -s python -p 'test_*.py'   # offline
python/test-ca-trust.sh
```

The CLI contract every implementation keeps is [specs/cli-contract.md](specs/cli-contract.md); all specs are indexed in [specs/](specs/README.md). See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE).
