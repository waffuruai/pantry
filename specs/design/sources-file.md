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
| `advisories` | `osv-dir` (a `path` only) | a folder of OSV records on this machine, matched here beside OSV's answers (below) |
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
2. **Kinds.** `yara`, `hashes`, `hosts`, `filenames` and `indicators`, the kinds kept as a file, and `advisories` as a folder of OSV records (`format = "osv-dir"`, [Advisories on this machine](#advisories-on-this-machine)). `hash-lookup` stays remote: a `path` for it is refused.
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

### Advisories on this machine

A source of the user's own with `kind = "advisories"` and `format = "osv-dir"` reads a folder of [OSV records](https://ossf.github.io/osv-schema/) on this machine: an offline machine that gets advisories by file copy, a team that keeps advisories for its internal packages, or a program that drives `wpantry` with advisories it already downloaded and checked. The rules of a local source above hold; in addition:

1. **Syntax.**
   - `format = "osv-dir"` requires `path`. An `osv-dir` source with a `url` (or with neither) is an error naming the source.
   - `path` with `kind = "advisories"` requires `format = "osv-dir"`. An `osv-api` source with a `path` is an error naming the source.
2. **The folder.**
   - One OSV record per `*.json` file, directly in the folder or in a subfolder of it one level down (`npm/TEAM-1.json`). A deeper subfolder is not read.
   - Only regular files and real subfolders: no symlink is followed, to a file or to a folder, so nothing outside the folder is read. The `path` itself may be a symlink, resolved once, and must name a folder.
   - A file's relative path is its path below the folder with `/` between parts (`npm/TEAM-1.json`). Files are read in byte-wise order of their relative paths.
3. **Limits** (`osv_dir::MAX_FILES`, `osv_dir::MAX_TOTAL_BYTES`).
   - Each file at most the source's `max_bytes` (capped as for every source of the user's own).
   - At most 100,000 files.
   - At most 1 GiB (1,073,741,824 bytes) read in all.
   - Over a limit, the read is refused: the source's last good load stays in effect and `wpantry sources` gives the reason as a failed fetch's. With no good load, the source is `unchecked`.
4. **Records.**
   - Each file is read with the same structures as a record from OSV. A file that isn't JSON, isn't a JSON object with a string `id` (no spaces or control characters), or has no usable `affected` entry (one naming a package's `ecosystem` and `name`, or a `GIT` range with a `repo`) is skipped and counted. The source still works.
   - Two files with the same `id`: the one later in byte-wise relative-path order wins.
5. **The pin.** A `sha256` pin is the SHA-256 of, for each `*.json` file read, in byte-wise order of its relative path: the relative path, a newline (`0x0a`), the file's size in bytes in decimal ASCII, a newline, then the file's bytes. For `a.json` holding `{}` and `npm/b.json` holding `[]`, it is the SHA-256 of `a.json\n2\n{}npm/b.json\n2\n[]`. With POSIX tools, from inside the folder:

   ```sh
   find . -maxdepth 2 -name '*.json' -type f | sed 's|^\./||' | LC_ALL=C sort |
     while IFS= read -r f; do printf '%s\n%s\n' "$f" "$(wc -c < "$f" | tr -d ' ')"; cat "$f"; done |
     shasum -a 256
   ```

   (A `.json` file in a subfolder two levels down, or a symlink, is not part of it.) A failed pin is refused like any other: the last good load stays.
6. **Freshness.** The folder is read again when its fingerprint differs from the one kept at its last good read: each file's relative path, size and modification time, and the path, pin and cap. The query TTL and OSV's change lists never apply to these records.
7. **Storage.** A good read replaces the source's records as a set, in the cache's `local_vulns` (one row per source and id) and `local_vuln_names` (the names each record is found by). A file removed from the folder takes its record with it on the next run. A source removed from the sources files takes all of its records; one turned off for the run, or kept for `--deep`, keeps them but is not used. Two sources never share rows, and OSV's own cached records (`vulns`) are never written.
8. **Matching.** For each package version a check asks OSV about, the records of the `osv-dir` sources in use (in the sources files' order) that name the package are judged on this machine with the same functions OSV's records use: `matches` for the package and ecosystem, `affects` for the version (the ecosystem's own version order), `fixed_versions` for the safe version and `affected_range` for the range. A withdrawn record never applies, as OSV's don't.
   - A record `affects` can't judge here (a range of git commits, or an ecosystem with no known version order) is not used. Where OSV's answers come from the change lists, such a version is asked of OSV's query API instead; there is no service to ask for a record of the user's own, so the check names the source and the record ids it couldn't judge and is reported `unchecked`.
   - A local record with the id of a record in OSV's answer for the same version is the same advisory: OSV's is used. Records whose ids or aliases meet are grouped into one finding by the alias grouping every advisory goes through.
   - A version OSV never answered (offline, first run) is still matched against the local records, and is still reported `unchecked` against OSV.
9. **Findings.** A finding from a local record is the same as one from OSV's, except its note and its link:
   - Its `note` ends with `(from your source <id>: <link>)`, or `(from your source <id>)` when the record has no link. A finding whose record is OSV's but whose group holds a local record ends with `(also in your source <id>)`.
   - Its link (`report --jsonl` `url`, `report --csv` `url`, the HTML report) is the record's first `references` entry of type `ADVISORY` or `WEB` when that entry's `url` is an `https` URL, and otherwise none. It is never an OSV.dev link unless the record itself gives one.
10. **Listing.** `wpantry sources` shows the folder where a host would be, how many records the last good load holds and how many files it skipped, and the last error. `--json` adds `records` and `skipped` (integers; null for every other source and before the first good load).

```toml
[[source]]
id = "team-advisories"
kind = "advisories"
format = "osv-dir"
path = "~/advisories"              # *.json records, flat or <ecosystem>/<id>.json
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
