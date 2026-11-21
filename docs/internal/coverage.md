# Coverage audits

How we check that Pantry catches what security agencies warn about. An audit takes a publisher's recent advisories, keeps the ones about software Pantry can see, and decides for each whether an affected install would be flagged. The gaps become issues.

## Publishers we audit against

| Publisher | Advisories | Last audit | Result | Issues |
|---|---|---|---|---|
| [Canadian Centre for Cyber Security](https://www.cyber.gc.ca/en/alerts-advisories) | Atom feed `https://www.cyber.gc.ca/api/cccs/atom/v1/get?feed=alerts_advisories&lang=en` (50 newest); every entry since 2018 from the site's JSON API, `https://www.cyber.gc.ca/api/cccs/threats/v1/get?lang=en&content_type=cccs_threat` | [2026-11-18](coverage/cccs-2026-11-18.md): the 150 newest | 83 in scope: 11 covered, 33 partial, 39 not | [#247](https://github.com/waffuruai/pantry/issues/247), [#248](https://github.com/waffuruai/pantry/issues/248) |
| [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | `cisagov/kev-data`, which Pantry already reads on every scan | not audited as a list yet | Pantry marks findings whose CVE is listed; matching outdated installs by product is [#221](https://github.com/waffuruai/pantry/issues/221) | |

Add a row when you audit a new publisher, and update it when you audit one again.

## Running an audit

1. **Advisories.** Take a fixed window (the last 90 days, or the newest 150 if there are more) and write down which, so the next audit can compare.
2. **Scope.** In scope: software on a laptop, workstation, developer machine or small self-hosted server (OS updates, browsers, apps, runtimes, lockfile packages, container images, self-hosted servers, editors). Out: network appliances and their firmware, ICS and OT, mobile, hardware, SaaS, enterprise suites Pantry can't see. Note the borderline ones.
3. **Coverage**, read from the code on `dev`, not the docs. *Covered*: inventoried on every platform the product runs on, and its fixed version is compared (OSV, endoflife.date, a release feed, KEV or the vendor's latest). *Partial*: some platforms, install methods or products are. *Not*: nothing would flag it. Say when only a "behind latest" warning would catch it, naming no CVE.
4. **CVEs.** For each CVE named, check whether OSV maps it to a package or repo Pantry queries, whether KEV lists it, and whether its CVE.org record has affected versions. This shows whether a gap is missing data or missing inventory.
5. **Write it up** in `coverage/<publisher>-<date>.md`: the counts, every advisory, the ranked gaps with what each needs (where to look, a version source, an advisory source), and what wasn't verified. File the gaps as one issue with a checklist and split them as they're picked up.
