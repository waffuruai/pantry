# The sources file

How wpantry declares, fetches and trusts every outside source, for [04-layout-and-sources](../04-layout-and-sources.md) phases 3, 4 and 6.

## Where it lives

| File | Role |
|---|---|
| `rust/crates/wpantry/assets/defaults/sources.toml` | The bundled sources, compiled into the binary. Their hosts make up `HOSTS` |
| `~/.config/wpantry/sources.toml` | The user's sources. Read on every run when it exists |
| `--sources FILE` | Read in place of the user's file for one run |
| `--add-sources FILE` | Repeatable. Its sources are added to the file in effect (`--sources`, or the user's file, which may not exist) for one run of `scan`, `fix` or `sources` |

The user's file can add a source, or change the `tier` of a bundled one (for example, `off`). It can't change a bundled source's URL: a different URL is a different source, with its own `id`.

An added file follows the same rules as the user's file. Its sources come after the user's, in the order the files are given. In addition:

- An `id` names one source across all the files. A source defined in the user's file or an earlier added file can't be defined again; the error names the `id` and both files.
- Any file may set only the `tier` of a bundled source, and the last one to set it wins. The user's own file may set any tier. An added file may only turn a bundled source up, towards more checking (`off` to `deep` or `default`, `deep` to `default`), judged against the tier in effect when that file is read; it can never turn one down or off, because a flag that adds sources must not make a run check less. An entry that would is an error (exit 2) naming the file, the `id` and the rule, and nothing from that file is applied (a file is used whole or not at all). Any other setting for a bundled `id` is refused, as in the user's file.
- An added file that is missing or can't be read is an error (exit 2), as is one that can't be used. Only the user's default file may be missing.
- `sync` and `rules` don't take `--add-sources`.

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
   - A source on this machine (`path`, below) reaches no host and is never asked about.
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

## Sources on this machine

A source of the user's own may give `path = "..."` in place of `url`. It is read from a file or folder on this machine and has the transport `local` and no host. The rules:

1. **Syntax.**
   - A source gives a `url` or a `path`, never both and never neither. Either mistake is an error naming the source.
   - A path is absolute (`/srv/rules`, or `C:\rules` and `\\server\share\rules` as TOML literal strings, `'C:\rules'`) or starts with `~/` for the home folder.
   - A relative path, a path with a `..` part, and an empty path are refused, naming the source. A path written for another system (`C:\...` on macOS) is refused when it is read.
   - `transport` may be left out or set to `local`; any other value with a `path` is an error.
   - Only a source of the user's own may have a `path`. On a bundled `id` it is refused like any other change to a bundled source.
2. **Kinds.** `yara`, `hashes`, `hosts`, `filenames` and `indicators`, the kinds kept as a file. `advisories` and `hash-lookup` stay remote: a `path` for them is refused.
3. **Reading.** Where a remote source is fetched into its copy (`rules/user-<id>.yar`, `rules/iocs/user-<id>.<kind>.txt`), a local one is read into the same copy, and everything after the copy is unchanged.
   - A regular file is read up to the source's `max_bytes`.
   - For `yara` only, the path may be a folder. Its `*.yar` files are joined in byte-wise name order, each followed by a newline, as Elastic's rules are. `max_bytes` applies to the joined text.
   - In a folder, only regular files directly inside it are read: no subfolders, no symlinks followed, nothing outside the folder. A folder with no `*.yar` file is refused.
   - YARA rules are read as UTF-8 text. A `.yar` file that is not UTF-8 (Latin-1, UTF-16) fails the source, naming the file, and the scan reports the source `unchecked`; nothing of the folder is used. A leading UTF-8 byte order mark is dropped.
   - A folder for any other kind is refused.
   - A `path` that is itself a symlink is resolved once; what it names must be a regular file or a folder.
4. **The same guards as a download.**
   - A `sha256` pin is checked over the bytes read (for a folder, over the joined text).
   - A copy that can't be read, is over its cap or fails its pin is refused. The last good copy stays, and the reason shows in `wpantry sources` as a failed fetch's does. With no good copy, the source is `unchecked`.
   - A gzip list is copied as it is and read like a downloaded one.
5. **Freshness.** A local source is read again when its fingerprint differs from the one kept at its last good read: the file's modification time and size, or, for a folder, the names, sizes and modification times of its `*.yar` files (and the path, pin and cap). `refresh` is ignored. `--offline` still reads it.
6. **Consent.** A local source sends nothing and reaches no host, so it is used without asking, `--no-input` included. It still obeys its `tier`: `off` is never used, `deep` only with `--deep`.
7. **Listing.** `wpantry sources` shows the path where a host would be. `--json` gives `"transport": "local"`, `"host": null` and the path as written in `"path"`; `"path"` is null for every other source.

```toml
[[source]]
id = "team-rules"
kind = "yara"
format = "yara"
path = "~/src/team-rules/yara"     # a folder of .yar files

[[source]]
id = "offline-hashes"
kind = "hashes"
format = "lines"
path = '/mnt/transfer/hashes.txt'
sha256 = "..."                     # optional, as for a download
```

## The bundled sources (phase 3)

Every source wpantry reads today, as entries:

| id | kind | format | tier |
|---|---|---|---|
| `osv` | advisories | osv-api | default |
| `cisa-kev` | kev | kev | default |
| `endoflife` | eol | endoflife | default |
| `cve-records` | advisories | vulnerability-lookup | default |
| `homebrew-advisories` | advisories | vulnerability-lookup-osv | default |
| `homebrew-formulae` | releases | homebrew-formula | default |
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
| `elastic` | yara | github-zip | off (ELv2: turned on with `tier = "default"` in the sources file) |

## Indicators

- Indicators are values, not patterns.
- Phase 4 stores each kind in the cache directory as a sorted, deduplicated set, keyed by source and version. Each entry keeps its family and source.
- A FileView's text is tokenised once into hosts, IPs, URLs and hashes, and each token is looked up in the store.
- The file's own sha256 is looked up against the hash sets.
- Persistence commands, `/etc/hosts` and, with `--deep`, live connections are looked up the same way.
- A hit names the source and family, so a user source's false positive can be turned `off` by its `id`.
