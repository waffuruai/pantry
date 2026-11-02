# Security policy

## Reporting a vulnerability

Email **security@waffuru.ai** with the subject "Security vulnerability in Pantry (wpantry)", or use GitHub's private vulnerability reporting on this repository (Security → Report a vulnerability). Include the wpantry version (`wpantry --version`), the platform, steps or a minimal reproducer, the impact as you see it, and how you want to be credited. Remove secrets and identifying data first: no scan output, credentials, email addresses, usernames, hostnames or filesystem paths. Do not open a public issue or pull request.

We acknowledge within 3 business days, tell you the severity and who is on it within 10 business days, fix by severity (CVSS: Critical 14 days, High 30, Medium 90, Low 180) and agree public disclosure with you, 90 days after the report at the latest, or when the fix ships if sooner. A fix is released with a GitHub security advisory and, for a vulnerability in wpantry itself, a CVE. We have no PGP key yet; say so in a first email if a report needs encryption and we will arrange a channel.

## Scope

In scope: the `wpantry` binary and the crates it is built from (`wpantry`, `wpantry-cli` in [`rust/`](rust/)), the release artifacts and their signatures, [`install.sh`](install.sh), and the scripts in [`ca-trust/`](ca-trust/). That includes any way to make wpantry run something it shouldn't, read or send more than it says, report a result that is wrong in a way that misleads you (a false "clean", a silenced finding), or accept an update, release or cache that was tampered with.

Out of scope: the data sources it asks (OSV.dev, CISA, endoflife.date, Homebrew, GitHub, deps.dev, HIBP), gitleaks and the other tools it runs, the packages and advisories it reports on, a vulnerability in one of wpantry's own dependencies (report it upstream, and tell us if we ship it unpatched past the deadlines above), denial of service, social engineering, automated scanner output with no shown impact, and waffuru.ai and the other Waffuru repositories, which have their own policies. A finding on your own machine is a reason to update, not a vulnerability in wpantry.

## Rules and safe harbour

Security research on wpantry done in good faith is welcome. Test only your own machines and accounts, or ones you are authorised to test; take only the proof you need; do not access, change, delete or keep anyone else's data; do not degrade a service others rely on, including the data sources wpantry asks; stop and report once you have proof. Within those rules and the full [vulnerability disclosure policy](https://waffuru.ai/security), your research is authorised: we will not take legal action against you, or refer you to law enforcement, for it, and we will say so to a third party that tries. Give us the time described above before anything is made public. If you are unsure whether something is covered, ask first at the address above. This applies to wpantry only; the services it talks to set their own rules.

## Credit

We name you in the fix's release notes and security advisory if you want that, in the form you choose. A reward is at our discretion, based on the severity of the impact; there is no published bounty programme yet. Duplicate reports are credited to the first.

## Threat model

wpantry reads a lot of your computer to tell you what is exposed, so it is built to take as little as it can.

- **It reads, and changes nothing unless asked.** A scan only reads. `--update` runs the fixes it marks unattended and user-level (Homebrew, pip, npm, cargo, rustup, uv, editor extensions); anything needing sudo, a vendor or a code change is printed for you to run.
- **Little leaves the machine.** Package names and versions go to OSV.dev, and public feeds are fetched (CISA KEV, endoflife.date, release feeds, the OpenSSF malicious-packages repo). File contents, paths and secrets are never sent. The hosts are a compiled-in list the binary refuses to go outside, over TLS verified against your machine's trust store. The email breach check is the one exception, and it runs only after you say yes (`wpantry breach`).
- **Secrets stay redacted.** gitleaks runs with `--redact`; the cache and the report hold the rule, file, line, commit and fingerprint, never the secret.
- **Unreachable is not clean.** A source that can't be reached, or a tool that is missing, is reported; it never makes the result look better.
- **No credentials of its own.** It holds no token. `HIBP_API_KEY` is read from the environment when you set it.
- **Stopgaps only when you say so.** The scripts in [`mitigations/`](mitigations/) (one per advisory that has no fix to install yet) and `ca-trust/fix-ca-trust.sh` are never run by a scan. You invoke them; they show what they will write and ask before touching anything (`--yes` for provisioning), and `--status` and `--dry-run` only read.

Known gaps are tracked as issues and listed in [docs/architecture.md](docs/architecture.md#what-the-port-left-open-and-where-it-closed); how releases are built, signed and verified is [docs/internal/release.md](docs/internal/release.md) and [docs/public/install.md](docs/public/install.md). The org-wide policies this file summarises (incident response, vulnerability management, the disclosure policy) live in [waffuruai/ops](https://github.com/waffuruai/ops/tree/dev/security).
