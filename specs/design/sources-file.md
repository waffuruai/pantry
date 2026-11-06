# The sources file

How wpantry declares, fetches and trusts every outside source, for [04-layout-and-sources](../04-layout-and-sources.md) phases 3, 4 and 6.

## Where it lives

| File | Role |
|---|---|
| `rust/crates/wpantry/assets/defaults/sources.toml` | The bundled sources, compiled into the binary. Their hosts make up `HOSTS` |
| `~/.config/wpantry/sources.toml` | The user's sources. Read on every run when it exists |
| `--sources FILE` | Read in place of the user's file for one run |

The user's file can add a source, or change the `tier` of a bundled one (for example, `off`). It can't change a bundled source's URL: a different URL is a different source, with its own `id`.

## An entry

```toml
[[source]]
id = "maltrail-recent"          # unique, kebab-case; names the source in findings and `wpantry sources`
kind = "hosts"                  # what it gives: advisories | kev | eol | releases | malicious-packages
                                #   | licenses | breaches | yara | hashes | hosts | filenames | hash-lookup
format = "maltrail"             # the reader in sources/formats/: osv-api | kev | endoflife | yara | yara-zip
                                #   | signature-base | maltrail | abusech-json | abusech-csv | lines | csv
url = "https://raw.githubusercontent.com/stamparm/maltrail/master/trails/static/malware/"
tier = "default"                # default | deep | off
refresh = "1d"                  # how stale a copy may be before it's fetched again
license = "MIT"
redistribute = true             # false: fetched on each machine, never put in a bundle (GPL, unlicensed, ELv2)
sha256 = ""                     # optional pin for a fixed file
signed_by = ""                  # optional: a key the release asset must be signed with (packslip)
max_bytes = 67108864            # the most read; more is an error, the last good copy is kept
```

**A lookup that receives data** names what it sends and is never fetched without consent:

```toml
[[source]]
id = "circl-hashlookup"
kind = "hash-lookup"
format = "circl"
url = "https://hashlookup.circl.lu/lookup/sha256/"
tier = "default"
sends = "sha256"                # only value allowed; a user source may not send anything else
consent = "hash-lookups"        # the consent it falls under; asked once
license = "CC0-1.0"
```

## Trust rules

1. **Bundled sources:**
   - Their hosts are compiled into `HOSTS`. A test fails if `HOSTS` and the bundled file disagree.
   - Changing one is a code change, reviewed like code.
2. **The user's sources:**
   - The first time a source with a new host is used, wpantry asks once. The answer is stored in the cache by `id` and URL.
   - With `--no-input` and no stored yes, the source is skipped and reported `unchecked`, never fetched silently.
3. **Sending data:**
   - A user source with `sends` may only send a SHA-256, and it needs its own consent beside the hash-lookup consent.
   - Nothing else in the file can make wpantry send data.
4. **Fetched data is hostile input:**
   - `max_bytes` is enforced while reading.
   - A failed pin or signature, a parse error, or an answer with nothing in it is refused: the last good copy stays (the refusal shows in `wpantry sources`), and with no good copy the source is `unchecked`.
   - Every reader is mutation-tested (`sources/mutate.rs`).
5. **Visibility:**
   - `wpantry sources [--json]` lists every source: `id`, kind, tier, host, licence, `redistribute`, last fetch, freshness and last error.
   - The report names the user sources a scan used.

## What a user's source may be (phase 3)

| kind | format | used as |
|---|---|---|
| `yara` | `yara` | a rules file beside ours and YARA Forge's (`rules/user-<id>.yar`) |
| `hashes`, `hosts`, `filenames` | `lines` (`value[;what]`, `regex;score` for file names) | indicators beside signature-base's (`rules/iocs/user-<id>.<kind>.txt`): hashes and hosts in the indicator store, matched by lookup (`Hash_IOC_User_<id>`, `IOC_C2_Host_User_<id>`); file names as regexes |
| `indicators` | `maltrail-csv` (`value,what,reference` lines, gzip or plain: Maltrail's `trails.csv`) | domains, addresses and URLs with their family, in the indicator store (`IOC_Host_User_<id>`); added in phase 4 for Maltrail Trails, whose licence keeps it out of the bundled file (#164) |
| `advisories` | `osv-api` | asked beside OSV.dev; with `osv` off, in its place |
| `hash-lookup` | `circl` or `yaraify` | asked about flagged files after the hash-lookup consent and its own; `sends = "sha256"` is required |

A bundled source's entry in the user's file may only set `tier`.

## The bundled sources (phase 3)

Every source wpantry reads today, as entries:

| id | kind | format | tier |
|---|---|---|---|
| `osv` | advisories | osv-api | default |
| `cisa-kev` | kev | kev | default |
| `endoflife` | eol | endoflife | default |
| `homebrew-casks`, `chrome-releases`, `firefox-releases`, `postgresql-security`, `arch-security` | releases | one each | default |
| `fedora-advisories` and the other distro feeds in `distros.rs` | advisories | one each | default |
| `deps-dev` | licenses | deps-dev-api | default with `--licenses` |
| `openssf-malicious-packages` | malicious-packages | ossf | default |
| `vscode-marketplace`, `open-vsx` | releases | one each | default |
| `haveibeenpwned`, `xposedornot` | breaches | one each | opt-in, as today |
| `pantry-rules` | yara | yara-zip | default (embedded snapshot, refreshed daily) |
| `yara-forge-full` | yara | yara-zip | deep |
| `signature-base` | hashes, hosts, filenames | signature-base | default |
| `feodo` | hosts | abusech-json | default |
| `sslbl` | hashes | abusech-csv | default |
| `maltrail-recent` | hosts | maltrail | default (built by the `pantry-rules` CI: malware categories changed in the last 90 days) |
| `maltrail` | hosts | maltrail | deep |
| `yaraify`, `circl-hashlookup` | hash-lookup | one each | default, after consent |
| `malwarebazaar` | hash-lookup | malwarebazaar | with the user's `ABUSECH_AUTH_KEY` |
| `elastic-protections` | yara | yara | off (ELv2: `wpantry rules --enable elastic`) |

## Indicators

- Indicators are values, not patterns.
- Phase 4 stores each kind in the cache directory as a sorted, deduplicated set, keyed by source and version. Each entry keeps its family and source.
- A FileView's text is tokenised once into hosts, IPs, URLs and hashes, and each token is looked up in the store.
- The file's own sha256 is looked up against the hash sets.
- Persistence commands, `/etc/hosts` and, with `--deep`, live connections are looked up the same way.
- A hit names the source and family, so a user source's false positive can be turned `off` by its `id`.
