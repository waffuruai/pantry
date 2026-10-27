# Security policy

## Threat model

wpantry reads a lot of your computer to tell you what is exposed, so it is built to take as little as it can.

- **It reads, and changes nothing unless asked.** A scan only reads. `--update` runs the fixes it marks unattended and user-level (Homebrew, pip, npm, cargo, rustup, uv, editor extensions); anything needing sudo, a vendor or a code change is printed for you to run.
- **Little leaves the machine.** Package names and versions go to OSV.dev, and public feeds are fetched (CISA KEV, endoflife.date, release feeds, the OpenSSF malicious-packages repo). File contents, paths and secrets are never sent. The email breach check is the one exception, and it runs only after you say yes (`wpantry breach`).
- **Secrets stay redacted.** gitleaks runs with `--redact`; the cache and the report hold the rule, file, line, commit and fingerprint, never the secret.
- **Unreachable is not clean.** A source that can't be reached, or a tool that is missing, is reported; it never makes the result look better.
- **No credentials of its own.** It holds no token. `HIBP_API_KEY` is read from the environment when you set it.

Known gaps are listed in [specs/](specs/README.md); the release-signing plan is [specs/01-rust-port.md](specs/01-rust-port.md#security).

## Reporting vulnerabilities

Do not open a public issue or pull request for a vulnerability in wpantry, and do not post scan output, credentials, email addresses, usernames, hostnames, filesystem paths or other identifying data. Send a minimal reproducer, with secrets and identifying values removed, through the repository owner's private security-reporting channel.
