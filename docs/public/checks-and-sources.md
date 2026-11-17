# What Pantry checks for

Pantry inventories what is installed on your computer and what your git repos lock, then asks a few public sources about only those exact versions. This page lists every check and every source.

See also: [usage.md](usage.md) (running it), [install.md](install.md), [architecture.md](architecture.md).

## What it checks

| Area | What |
|---|---|
| Malware | YARA rules over the files malware lands in: the top two levels of Downloads, Desktop and the temp directories, the programs launch items and autostart entries start, and the executables in your repos; `--deep` reads all of `~` with every system's rules. Rules: [YARA Forge](https://github.com/YARAHQ/yara-forge)'s `full` package (about 12,000 rules from 40+ projects, fetched to your machine) plus any `.yar` you add to the rules directory; by default only this system's and any system's. A malware hit fails, Critical; a hacking tool or unwanted program warns, High; a heuristic warns. Each file's hashes and the hosts, addresses and URLs it names (ASCII or UTF-16) are looked up in the indicator lists: a known-bad hash fails, Critical; naming a known command-and-control or malware host warns, with the first one named and how many more. Results are cached per file until it or the rules change; a refreshed indicator list is matched against the cache without rereading files. Engine: [wpantry-yara](../../rust/crates/wpantry-yara), written here; rules and adding your own: [malware.md](malware.md) |
| Your repos' dependencies | The lockfiles in every git repo it finds: Cargo, npm, pnpm, yarn, bun, deno, Swift, Go, uv, poetry, pip, Pipenv, Bundler, Composer, Maven, Gradle, NuGet, Pub, Hex, Conan |
| Committed secrets | [gitleaks](https://github.com/gitleaks/gitleaks) over each repo's whole history once, then only new commits on its branches. Files over 10 MB are skipped, in history too (git is told they're binary). Secrets are never printed or stored: only rule, file, line and commit. A repo's `.gitleaks.toml` is reported, not obeyed; its `.gitleaksignore` is obeyed |
| Malicious packages | Every package name against the OpenSSF malicious-packages index; VS Code's malicious-extension list |
| AI harnesses | The MCP servers your repos and coding agents (Claude Code, Codex, Cursor, Gemini CLI and others) start (an unpinned `npx some-server` warns: it runs whatever is latest), their plugins, skills and bundled npm packages |
| Install scripts | Dependencies that run code when installed, outside an allowlist |
| Suspicious code | Strings decoded at run time and fed to `eval`, encoded payloads, hand-rolled decoders and escaped source; `sudo`, setuid, `curl \| sh` and persistence in files that run commands; credential stores read and sent; code asking a crypto wallet to sign, approve or hand the account over; clipboard clippers; third-party scripts without an integrity hash; traffic to bare IPs; typosquatted dependencies; prebuilt binaries with no source; AI prompts that profile a person to monetize their assets; card data in the clear (PCI DSS); hardcoded and weak passwords; keyloggers. In the repos and, on a machine scan, every installed editor, agent and browser extension ([suspect-code.md](suspect-code.md)) |
| Programs listening with MPTCP on | A Go module whose `go` line is 1.24 or newer and whose source listens for TCP (`net.Listen`, `ListenConfig`, `http.ListenAndServe`, gRPC, fasthttp) without opting out (`SetMultipathTCP(false)`, `godebug multipathtcp=0` in `go.mod`, a `//go:debug` directive, or `GODEBUG=multipathtcp=0` in a Dockerfile, compose file, Kubernetes manifest, systemd unit or `.env`), and any source that asks for MPTCP by name (`IPPROTO_MPTCP`, socket2's `Protocol::MPTCP`, `SetMultipathTCP(true)`). Go 1.24 listens with Multipath TCP on Linux by default, which reaches [CVE-2026-98432](https://osv.dev/vulnerability/CVE-2026-98432) through the program, not only the kernel. A `project` warning (Critical, `fixed` empty, counted as unfixed) with the opt-out as the step, until the kernel under it is fixed |
| Hidden text | Unicode that reads one way and runs another (bidi overrides, Trojan Source), invisible tag and zero-width characters that smuggle instructions to an AI assistant, identifiers mixing scripts, and identifiers packed with weapon and poison vocabulary so an AI reviewer refuses to read the code (`AI-BAIT`, terms in `rust/crates/wpantry/assets/defaults/bait.toml`) |
| Documents and images | PDFs, Office files, RTF and images for the shapes document malware takes (JavaScript on open, macros, remote templates, DDE, programs posing as images, SVG scripts, …), plus [ClamAV](https://www.clamav.net/) when installed. In the repos and, on a machine scan, the top of `~/Downloads`, `~/Desktop` and `~/Documents` ([documents.md](documents.md)) |
| Repo hooks | Code a repo runs the moment it is opened or installed: Claude Code and Gemini hooks, MCP servers kept in the repo, VS Code tasks on folder open, devcontainer commands, direnv, the repo's own install scripts, gyp expansions, native addons; plus the file names, packages, hosts and hashes of known hijacked-repo campaigns. A hook you have read goes in your hooks policy (`~/.config/wpantry/hooks.toml`) as a `hooks = [ { file, when, command } ]` entry (the warning's fix text gives it) and is counted, not listed, until its command changes; a hook that fails is never accepted |
| Licenses | With `--licenses`, dependency licenses outside an allowlist |
| Container images | The images your repos build from |
| The OS | Debian, Ubuntu, Alpine, SUSE packages (from the package database), dnf distros, Arch; macOS Software Update |
| Installed software | Runtimes and compilers (every version a version manager keeps, not just PATH), package managers, CLI tools, datastores, Docker, global pip/npm/gem/cargo/pipx packages, Homebrew formulae (`brew vulns`), apps, browsers, Electron apps, editor extensions; mise itself against OSV and its latest release |
| Homebrew without `brew` | Bottles poured into the Cellar by mise's `brew:` engine (no `brew` command, so no `brew vulns`): each formula the tool catalog knows is checked against OSV and endoflife.date; the rest are reported "not checked" |
| End of life | Runtimes and datastores past their end-of-life date fail |
| Certificate authorities | System, OpenSSL, Homebrew, certifi, pip and Node trust stores against the leaked eMudhra CAs (`wpantry fix ca-trust` distrusts them until the OS update ships) |
| Clipboard clippers | Found in files; Pantry never reads or writes the clipboard. Every launch agent and daemon, autostart entry and user service is read for the program it runs: touching the clipboard with wallet addresses (EVM, Bitcoin, Tron, Solana, XRP, Stellar and more) or the patterns that recognise them fails (`CLIPPER-PERSISTENCE`); touching it from a temporary or hidden place warns. A browser extension asking for both `clipboardRead` and `clipboardWrite` warns (`CLIPPER-EXTENSION`) and fails when its code has the clipper shape (`SUSPECT-CLIPBOARD-SWAP`). Watching the clipboard live is a resident watchdog's job |
| The machine's settings | FileVault or LUKS, the firewall and its logging, Gatekeeper, SIP and Secure Boot, automatic updates and time sync, Remote Login, AirDrop and the sharing services, guest and automatic login, an everyday account that isn't an administrator, the screen lock, XProtect and XProtect Remediator, whether DNS leaves the machine encrypted (DoT or DoH; plain DNS to an internal resolver only warns), and more ([posture.md](posture.md)); `--no-posture` skips them |
| Persistence | Every place a program can come back from after a reboot (launch agents and daemons, login items, cron, at, extensions and plugins, shell startup files, `DYLD_INSERT_LIBRARIES`, systemd units, XDG autostart, `/etc/ld.so.preload`, …), compared with the last scan's list: a new item warns (`PERSISTENCE-NEW`); library injection, a broken signature or a temporary or hidden location warns every scan ([posture.md](posture.md#persistence)) |
| Developer-tool guardrails | Editor extensions wait 72 hours before a new version installs (`wpantry fix extension-cooldown`), git hooks that check commits |

`--no-machine` limits a run to the repo rows: dependencies, secrets, malicious packages, harnesses, install scripts, suspicious code, programs listening with MPTCP on, hidden text, documents and images, repo hooks, licenses, images. What a run could not check shows as "not checked", never clean.

A finding **fails** when it is a known vulnerability with a released fix, past end of life, a known malicious package, a committed secret from a provider-specific rule, a clipper or a clipper's swap, or a Critical or High posture setting.

It **warns** when there is no fix yet, an app is outdated, an MCP server is unpinned, an install script runs, a generic secret rule matched, a Medium or Low posture setting is off, or a persistence item is new, injects a library, has a broken signature or runs from a hidden place.

## Sources

![Where the threat data comes from: the inventory becomes (ecosystem, name, version) triples; the SQLite cache keeps every answer current from OSV's change lists; the rest go to OSV.dev and the feeds; judgement groups aliases into one finding and picks the safe version; the report fails, warns, or says not checked. Local tools run here and send nothing](../images/sources.png)

[Full size](../images/sources.png) · [SVG source](../images/sources.svg)

These are the only hosts the binary connects to.

- **One list.** Every source is declared in one file compiled into the binary, [`sources.toml`](../../rust/crates/wpantry/assets/defaults/sources.toml): URL, refresh period, how much is read, licence, what a request sends. The host list (`net::HOSTS`) is that file's hosts.
- **Enforced.** Any other URL is refused before connecting. A redirect is followed only to a listed host, and an `Authorization` header never follows it off the first host. A test checks every source against the list.
- **Every request** is https, verified against your machine's trust store (a CA you distrust is distrusted here too), names `wpantry` in its User-Agent, times out after 30 seconds, and uses `HTTPS_PROXY` when set.
- **Cache.** Answers live in `~/.cache/wpantry/wpantry.db`; nothing expires. OSV's answers are kept current from its change lists (only what changed since the last run is read). Each feed, after its refresh period (a day for most), is asked whether it changed and downloaded only when it did.
- **Offline.** `--offline` uses only the cache. A source that can't be reached and has nothing cached is reported "not checked".

| Source | Answers | What is sent |
|---|---|---|
| [OSV.dev](https://osv.dev) (`api.osv.dev`) | Known vulnerabilities, affected and fixed versions, severity, aliases, for every ecosystem OSV covers (crates.io, npm, PyPI, Go, RubyGems, Maven, Debian, Ubuntu, Alpine, SUSE, and more) | The (ecosystem, name, version) of what is installed or locked. No file contents, paths or secrets. Workspace members and local packages are not sent |
| OSV's change lists (`osv-vulnerabilities.storage.googleapis.com`) | Which advisories changed since the last run, per ecosystem, newest first: only the top of the list is read, down to the last change applied, and only the records that changed are downloaded | The name of each ecosystem you have packages in (in the list's path), and the ids of the changed advisories |
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | The `KEV` mark: vulnerabilities seen exploited in the wild, which the report puts first | Nothing; the catalog is downloaded |
| OSV.dev's record for a CVE, then [CVE.org](https://www.cve.org) (`cveawg.mitre.org`) | A CVSS score for an advisory whose records carry none (the Go project publishes none): OSV's copy of the CVE first, then the CVE record itself, the publisher's score or the one CISA adds when it reviews it. Each answer is kept a week | The CVE id, only for findings that apply here and have no score |
| [EPSS](https://www.first.org/epss/) (FIRST; scores by Empirical Security, `epss.empiricalsecurity.com`) | For every CVE, the probability it is exploited in the next 30 days and its percentile: the reports' EPSS column, and the order within a severity; daily | Nothing; the whole file (about 3 MB) is downloaded, so no CVE list leaves the machine |
| [endoflife.date](https://endoflife.date) | End-of-life dates for runtimes and datastores | The product name |
| [OpenSSF malicious-packages](https://github.com/ossf/malicious-packages) | Known malicious package names, per ecosystem | Nothing; the index is cloned with git |
| [deps.dev](https://deps.dev) | Dependency licenses, with `--licenses` | The (ecosystem, name, version) of your repos' dependencies |
| [Homebrew](https://brew.sh) (`formulae.brew.sh`, `brew vulns`) | The cask catalog, to find outdated apps; `brew vulns` for installed formulae | Nothing; the catalog is downloaded and `brew` runs locally |
| [Arch Linux security tracker](https://security.archlinux.org) | Advisories for Arch packages | Nothing; the tracker is downloaded |
| Chrome and Firefox release feeds (`versionhistory.googleapis.com`, `product-details.mozilla.org`) | The current browser versions | The platform |
| [PostgreSQL security page](https://www.postgresql.org/support/security/) | Fixed PostgreSQL releases | Nothing; the page is downloaded |
| VS Code Marketplace and [Open VSX](https://open-vsx.org) | Editor extension versions, and VS Code's list of malicious extensions | The extension ids |
| GitHub releases (`api.github.com`) | The latest release of tools without a feed (mise); `GITHUB_TOKEN` lifts the anonymous rate limit | The repository name |
| [signature-base](https://github.com/Neo23x0/signature-base) IOC lists (`api.github.com`) and [abuse.ch Feodo Tracker](https://feodotracker.abuse.ch) (`feodotracker.abuse.ch`) | Known-bad file hashes, file names malware uses, and command-and-control hosts, for the malware scan, matched by lookup (a million indicators cost what a thousand do); daily | Nothing; the lists are downloaded |
| [YARAify](https://yaraify.abuse.ch) (`yaraify-api.abuse.ch`), [CIRCL hashlookup](https://hashlookup.circl.lu) (`hashlookup.circl.lu`) and, with your `ABUSECH_AUTH_KEY`, [MalwareBazaar](https://bazaar.abuse.ch) (`mb-api.abuse.ch`) | Whether a file the malware scan flagged is known malware (and which family) or known-good software | The flagged file's SHA-256 only, never the file, its name or path, only after you say yes once, at most 50 a scan; `--no-online-hash` never sends it |
| [YARA Forge](https://github.com/YARAHQ/yara-forge) releases (`api.github.com`, then `release-assets.githubusercontent.com` or `objects.githubusercontent.com`, where GitHub redirects the download) | The malware scan's community rules, at most daily | Nothing; the package is downloaded |
| [Have I Been Pwned](https://haveibeenpwned.com) or [XposedOrNot](https://xposedornot.com) | Whether an email address appears in a breach | Your email address, only after `wpantry breach --enable` and only after you say yes; `HIBP_API_KEY` selects Have I Been Pwned |

## Custom sources

### Your own sources

`wpantry sources` lists every source, when it was last fetched and what last went wrong.

A sources file of your own, `~/.config/wpantry/sources.toml` (or `--sources FILE`), in the bundled file's format, can:

- turn a source off (`tier = "off"`);
- add YARA rules; hash, host and file-name lists; an indicator set in Maltrail's `trails.csv` format; an OSV-compatible API; or a hash lookup.

A source of yours on a host Pantry doesn't already ask, or one that sends anything (a hash lookup may send a flagged file's SHA-256, nothing else), is used only after you say yes, once. With `--no-input` and no yes, it is reported not checked. Details: [the sources file](../../specs/design/sources-file.md).

### Third-party sources

Sources Pantry knows how to read but doesn't ship or fetch by default, usually because of their licence. Add one to your sources file to use it.

**Maltrail's trails.** [Maltrail Trails](https://github.com/stamparm/trails) is about 1.85 million malicious domains, addresses and URLs, each with its family, published daily. Its licence allows defending systems you operate but not building it into something offered to others, so Pantry doesn't ship or fetch it by default. To use it, add it to your sources file:

```toml
[[source]]
id = "trails"
kind = "indicators"
format = "maltrail-csv"
url = "https://github.com/stamparm/trails/releases/latest/download/trails.csv.gz"
tier = "default"          # or "deep": only with --deep
refresh = "1d"
license = "Maltrail Trails Community Data License 1.0"
```

Pantry then fetches it daily, inflates it, and matches every file the malware scan reads against it by lookup. A file naming one of its hosts warns under `IOC_Host_User_trails`, with the host and family (`names evil.example, interlock (malware) (trails)`).

## Local tools and references

Local tools run on your machine and send nothing: [gitleaks](https://github.com/gitleaks/gitleaks) (secrets), `git`, `openssl` (trust stores), [ClamAV](https://www.clamav.net/) (documents and images, when installed), `brew` and `docker` or podman (when present), and the OS's package database and `softwareupdate`. `wpantry tools` lists them and which are missing.

- Posture checks follow the [CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks) for macOS and Linux and read settings locally ([posture.md](posture.md)).
- The certificate-authority check follows the [eMudhra advisory](https://emudhra.we-have-a-problem.com/).
- The lockfile readers and OS package-database mapping were written against [osv-scanner](https://github.com/google/osv-scanner) and [osv-scalibr](https://github.com/google/osv-scalibr)'s test fixtures, so a lockfile reads the same here as there.
- The projects and data this stands on are credited in the README's [acknowledgements](../../README.md#acknowledgements).
