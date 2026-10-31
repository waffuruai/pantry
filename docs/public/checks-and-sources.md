# What wpantry checks, and where the answers come from

wpantry inventories what is installed on your computer and what your git repos lock, then asks a few public sources only about those exact versions. This page lists every check and every source. For running it, see [usage.md](usage.md); for installing it, [install.md](install.md); for how the scanner is put together, [architecture.md](../architecture.md).

## What it checks

| Area | What |
|---|---|
| Your repos' dependencies | The lockfiles in every git repo it finds: Cargo, npm, pnpm, yarn, bun, deno, Swift, Go, uv, poetry, pip, Pipenv, Bundler, Composer, Maven, Gradle, NuGet, Pub, Hex, Conan |
| Committed secrets | Each repo's whole git history, with [gitleaks](https://github.com/gitleaks/gitleaks); secrets are never printed or stored, only the rule, file, line and commit |
| Malicious packages | Every package name against the OpenSSF malicious-packages index; VS Code's malicious-extension list |
| AI harnesses | The MCP servers your repos and coding agents (Claude Code, Codex, Cursor, Gemini CLI and others) start (an unpinned `npx some-server` warns: it runs whatever is latest), their plugins, skills and bundled npm packages |
| Install scripts | Dependencies that run code when installed, outside an allowlist |
| Licenses | With `--licenses`, dependency licenses outside an allowlist |
| Container images | The images your repos build from |
| The OS | Debian, Ubuntu, Alpine, SUSE packages (from the package database), dnf distros, Arch; macOS Software Update |
| Installed software | Runtimes and compilers (every version a version manager keeps, not just PATH), package managers, CLI tools, datastores, Docker, global pip/npm/gem/cargo/pipx packages, Homebrew formulae (`brew vulns`), apps, browsers, Electron apps, editor extensions; mise itself against OSV and its latest release |
| End of life | Runtimes and datastores past their end-of-life date fail |
| Certificate authorities | System, OpenSSL, Homebrew, certifi, pip and Node trust stores against the leaked eMudhra CAs (`ca-trust/fix-ca-trust.sh` distrusts them) |
| The machine's settings | FileVault or LUKS, the firewall, Gatekeeper and SIP, automatic updates, Remote Login and the sharing services, guest and automatic login, the screen lock, and more ([posture.md](posture.md)); `--no-posture` skips them |

`--no-machine` limits a run to the repo rows (dependencies, secrets, malicious packages, harnesses, install scripts, licenses, images). What a run could not check shows up as "not checked", never as clean.

A finding fails when something here has a known vulnerability with a released fix, is past end of life, is a known malicious package, is a committed secret from a provider-specific rule, or is a Critical or High posture setting. It warns when there is no fix yet, an app is outdated, an MCP server is unpinned, an install script runs, a generic secret rule matched, or a Medium or Low posture setting is off.

## Sources

These are the only hosts the binary will connect to: the list is compiled in (`net::HOSTS`), any other URL is refused before a connection is made, and a test checks every source against it. Every request is https, verified against your machine's own trust store (so a certificate authority you distrust is distrusted here too), names wpantry in its User-Agent, times out after 30 seconds, and goes through `HTTPS_PROXY` when it is set. Answers are cached in `~/.cache/wpantry/wpantry.db` for a day; `--offline` uses only the cache, and a source that can't be reached and has nothing cached is reported "not checked".

| Source | Answers | What is sent |
|---|---|---|
| [OSV.dev](https://osv.dev) (`api.osv.dev`) | Known vulnerabilities, affected and fixed versions, severity, aliases, for every ecosystem OSV covers (crates.io, npm, PyPI, Go, RubyGems, Maven, Debian, Ubuntu, Alpine, SUSE, and more) | The (ecosystem, name, version) of what is installed or locked. No file contents, paths or secrets. Workspace members and local packages are not sent |
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | The `KEV` mark: vulnerabilities seen exploited in the wild, which the report puts first | Nothing; the catalog is downloaded |
| [endoflife.date](https://endoflife.date) | End-of-life dates for runtimes and datastores | The product name |
| [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) | Known malicious package names, per ecosystem | Nothing; the index is cloned with git |
| [deps.dev](https://deps.dev) | Dependency licenses, with `--licenses` | The (ecosystem, name, version) of your repos' dependencies |
| [Homebrew](https://brew.sh) (`formulae.brew.sh`, `brew vulns`) | The cask catalog, to find outdated apps; `brew vulns` for installed formulae | Nothing; the catalog is downloaded and `brew` runs locally |
| [Arch Linux security tracker](https://security.archlinux.org) | Advisories for Arch packages | Nothing; the tracker is downloaded |
| Chrome and Firefox release feeds (`versionhistory.googleapis.com`, `product-details.mozilla.org`) | The current browser versions | The platform |
| [PostgreSQL security page](https://www.postgresql.org/support/security/) | Fixed PostgreSQL releases | Nothing; the page is downloaded |
| VS Code Marketplace and [Open VSX](https://open-vsx.org) | Editor extension versions, and VS Code's list of malicious extensions | The extension ids |
| GitHub releases (`api.github.com`) | The latest release of tools without a feed (mise); `GITHUB_TOKEN` lifts the anonymous rate limit | The repository name |
| [Have I Been Pwned](https://haveibeenpwned.com) or [XposedOrNot](https://xposedornot.com) | Whether an email address appears in a breach | Your email address, only after `wpantry breach --enable` and only after you say yes; `HIBP_API_KEY` selects Have I Been Pwned |

Local tools run on your machine and send nothing: [gitleaks](https://github.com/gitleaks/gitleaks) for secrets, `git`, `openssl` for the trust stores, `brew` and `docker` (or podman) when present, and the OS's own package database and `softwareupdate`. `wpantry tools` lists them and which are missing.

The posture checks follow the [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) for macOS and Linux and read settings locally ([posture.md](posture.md)). The certificate-authority check follows the [eMudhra advisory](https://emudhra.we-have-a-problem.com/). The lockfile readers and the OS package-database mapping were written against [osv-scanner](https://github.com/google/osv-scanner) and [osv-scalibr](https://github.com/google/osv-scalibr)'s test fixtures, so a lockfile reads the same way here as there. The projects and data this stands on are credited in the README's [acknowledgements](../../README.md#acknowledgements).
