# Security policy

## Threat model

wpantry reads a lot of your computer to tell you what is exposed, so it is built to take as little as it can.

- **It reads, and changes nothing unless asked.** A scan only reads. `--update` runs the fixes it marks unattended and user-level (Homebrew, pip, npm, cargo, rustup, uv, editor extensions); anything needing sudo, a vendor or a code change is printed for you to run.
- **Little leaves the machine.** Package names and versions go to OSV.dev, and public feeds are fetched (CISA KEV, endoflife.date, release feeds, the OpenSSF malicious-packages repo). File contents, paths and secrets are never sent. The email breach check is the one exception, and it runs only after you say yes (`wpantry breach`).
- **Secrets stay redacted.** gitleaks runs with `--redact`; the cache and the report hold the rule, file, line, commit and fingerprint, never the secret.
- **Unreachable is not clean.** A source that can't be reached, or a tool that is missing, is reported; it never makes the result look better.
- **No credentials of its own.** It holds no token. `HIBP_API_KEY` is read from the environment when you set it.

Known gaps are listed in [specs/](specs/README.md); the release-signing plan is [specs/01-rust-port.md](specs/01-rust-port.md#security).

## Scope

In scope: the `wpantry` binary and the crates it is built from (`wpantry`, `wpantry-cli` in [`rust/`](rust/)), the release artifacts and their signatures, [`install.sh`](install.sh), and the scripts in [`ca-trust/`](ca-trust/). That includes any way to make wpantry run something it shouldn't, read or send more than it says, report a result that is wrong in a way that misleads you (a false "clean", a silenced finding), or accept an update, release or cache that was tampered with.

Out of scope: the data sources it asks (OSV.dev, CISA, endoflife.date, Homebrew, GitHub, deps.dev, HIBP), gitleaks and the other tools it runs, the packages and advisories it reports on, and waffuru.ai and the other Waffuru repositories, which have their own policies. A finding on your own machine is a reason to update, not a vulnerability in wpantry.

## Reporting vulnerabilities

Do not open a public issue or pull request for a vulnerability in wpantry, and do not post scan output, credentials, email addresses, usernames, hostnames, filesystem paths or other identifying data. Send a minimal reproducer, with secrets and identifying values removed, to [hello@waffuru.ai](mailto:hello@waffuru.ai?subject=Security%20vulnerability%20in%20Pantry%20%28wpantry%29) with the subject "Security vulnerability in Pantry (wpantry)", or use GitHub's private vulnerability reporting on this repository (Security → Report a vulnerability). We acknowledge reports within three business days, say what we found, and credit you in the fix's release notes if you want that.

## Safe harbour

Security research on wpantry done in good faith is welcome. We will not take legal action against you, or refer you to law enforcement, for research that stays within this scope, uses only your own machines and accounts (or ones you are authorised to test), does not access, change or delete anyone else's data, does not degrade a service others rely on, and gives us a reasonable time to fix what you found before it is made public. If you are unsure whether something is covered, ask first at the address above. This applies to wpantry only; the services it talks to set their own rules.
