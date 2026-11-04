# Download guard: what it watches, what it scans and how it holds

The detail behind [03-download-guard.md](../03-download-guard.md): the watch rules, the auto-execution risks and how each is handled, the scan worker's sandbox, the quarantine store and the event object. Status: draft, 2026-11-04. Nothing here is built.

## Watch rules

One recursive watch per platform, filtered in process. A path is considered once its writes have settled: no event for 1 s and the size unchanged, and never while it still has a browser's partial-download name (`.crdownload`, `.part`, `.download` bundles, `.opdownload`).

| Watched | macOS | Linux | Considered |
|---|---|---|---|
| `~/Downloads`, `~/Desktop` | FSEvents, file-level events | inotify `IN_CLOSE_WRITE`, `IN_MOVED_TO`, per directory | every new file |
| Files carrying `com.apple.quarantine` | any watched path | n/a (no equivalent) | every new file with the xattr |
| New executables and bundles under `~` | the same FSEvents stream on `~` | inotify on `~` top level, `~/bin`, `~/.local/bin` and the configured source roots | Mach-O, ELF, `#!` scripts, any file with an execute bit, `.app`, `.pkg`, `.mpkg`, `.dmg`, `.command`, `.tool`, `.terminal`, `.workflow`, `.shortcut`, `.desktop`, `.AppImage` |
| New git repos under `~` | a new `.git/HEAD` | the same, under the source roots | the checkout: executables, scripts, auto-run-on-open files (below) |
| Newly mounted volumes | `/Volumes` | `/media/$USER`, `/run/media/$USER` | app bundles, `.pkg` and scripts at the volume's top two levels |

Excluded without a read: `~/Library`, `~/.cache`, `~/.cargo`, `~/.rustup`, `~/.npm`, `~/.local/share/mise`, and any path under `target/`, `build/`, `dist/`, `.build/`, `DerivedData/`, `node_modules/`, `.venv/`, `venv/`, `.git/objects/`, `__pycache__/`. FSEvents takes up to eight exclusion prefixes at the stream (`FSEventStreamSetExclusionPaths`); the rest are dropped in process before any read. The list is the scan's own skip list plus build outputs, and `guard.exclude` in the policy file adds to it.

Linux watches are per directory, so the whole of `~` is not watched there: inotify needs one watch per directory, and `fanotify` on a filesystem needs `CAP_SYS_ADMIN`. The source roots default to `~/src`, `~/code`, `~/Development`, `~/projects`, `~/repos` and `~/git` where they exist.

### Burst limits

A directory that gains more than 200 files in 10 s (an unzip, a clone, a build in an unexcluded path) switches to a summary pass: executables, scripts and auto-run files now, the rest when the machine is idle. A path is scanned at most once per (device, inode, size, mtime).

## Auto-execution risks

Some files run, or are parsed by system code, without the person choosing to run them. The guard cannot win a race with a parser that fires on the write, so for those it relies on the OS's own sandbox and on getting the file out of the indexed paths fast; for the rest it relies on the quarantine xattr and on holding.

| Risk | What happens | What the guard does |
|---|---|---|
| Safari "Open 'safe' files after downloading" | Safari opens archives, disk images and documents it calls safe; a `.zip` is unpacked next to the download | A posture check warns while it is on (`AutoOpenSafeDownloads` in Safari's container preferences). Everything unpacked is a new file and is scanned like one; an app bundle unpacked without the quarantine xattr gets it |
| [CVE-2022-22616](https://nvd.nist.gov/vuln/detail/CVE-2022-22616) | A gzip-compressed zip auto-unpacked by Safari left the extracted app without the quarantine xattr, so Gatekeeper never checked it (fixed in macOS 12.3) | Any new bundle or executable in `~/Downloads` without the xattr gets it and is flagged `quarantine-missing`; on an unpatched macOS the scan's OS finding already fails |
| [CVE-2022-42821](https://nvd.nist.gov/vuln/detail/CVE-2022-42821) ("Achilles") | An archive whose files carry ACLs denying extended-attribute writes stops the quarantine xattr being set (fixed in macOS 13, 12.6.2, 11.7.2) | A new file whose ACL denies `writeextattr` or `writesecurity` is held as `gatekeeper-bypass`; the guard reads ACLs with `acl_get_file`, it never changes them in place |
| Script-only app bundles ([CVE-2021-30657](https://nvd.nist.gov/vuln/detail/CVE-2021-30657)) | A bundle with no `Info.plist` and a script as its executable skipped Gatekeeper's assessment (fixed in macOS 11.3) | Held as `gatekeeper-bypass` |
| Quick Look | Selecting or previewing a file parses it. Since macOS 15 only sandboxed previewer app extensions run; legacy `.qlgenerator` plugins no longer load (to confirm in phase 2) | No guard can pre-empt a preview. Held files move to a store Spotlight and Finder never index (below); third-party previewers are in the persistence inventory ([#125](https://github.com/waffuruai/pantry/issues/125)) |
| Spotlight importers | `mdworker` parses a file soon after it is written | As Quick Look. A new `.mdimporter` or `.qlgenerator` bundle under `~` is held: installing one is persistence, not a download |
| Linux thumbnailers | `tumbler`, GNOME's thumbnailers and Tracker parse new files in indexed paths; GNOME runs its thumbnailers under `bwrap` | As above; the store carries `.trackerignore` and `.nomedia` so Tracker skips it, and lives outside `~/Pictures`, `~/Videos` and the XDG user dirs |
| `.command`, `.tool` | Double-click opens Terminal and runs it | Scanned as a script; quarantine xattr added; a match holds it |
| `.terminal` | A Terminal settings file whose `CommandString` runs on open | A `CommandString` that downloads, decodes or executes is `risky`; with a malware match it is held |
| `.fileloc`, `.inetloc`, `.webloc` | A bookmark that LaunchServices opens; a `file://` target can launch a local program | A `file://` or `x-` scheme target pointing at an executable, a script or `/bin` is `risky` |
| Shortcuts (`.shortcut`) | Importing runs nothing, but a shortcut can run shell scripts when run | A signed shortcut with a "Run Shell Script" or "Run AppleScript" action is `risky`, never held on that alone |
| Office macros | `vbaProject.bin` in `.docm`, `.xlsm`, `.pptm`, and in OLE `.doc`, `.xls`; `AutoOpen`, `Document_Open`, `Workbook_Open` run on open when macros are enabled | Read in memory from the OOXML zip or the OLE stream: macros alone are `risky`; auto-run entry points with `Shell`, `MacScript`, `CreateObject`, URL download or decode are held by rule. This builds on the document screening of [#67](https://github.com/waffuruai/pantry/issues/67) |
| PDF JavaScript | `/OpenAction` or `/AA` with `/JS`, `/JavaScript`, `/Launch`, `/EmbeddedFile`; Acrobat runs them, Preview does not | JavaScript or `/Launch` with an auto action is `risky`; a malware rule match is held |
| Linux `.desktop` | `Exec=` runs when launched; GNOME needs the file marked trusted, KDE asks; in `~/.config/autostart` it runs at login | A new `.desktop` in Downloads or Desktop is scanned and its `Exec=` line read; one in an autostart directory is persistence ([#125](https://github.com/waffuruai/pantry/issues/125)) and held if new and unsigned by a package |
| Auto-run on open in a cloned repo | `.vscode/tasks.json` with `"runOn": "folderOpen"`, `.envrc` (direnv after `direnv allow`), `.devcontainer` `postCreateCommand`, a `core.hooksPath` setup script, package lifecycle scripts | Reported by the existing repo checks (`hooks`, `suspect`) on the new clone, now within seconds of the clone, not at the next scan |
| Pipes | `curl … \| sh` and `bash -c "$(curl …)"` never write a file | Out of scope; the guard sees only what lands on disk |

`risky` means the guard keeps or adds the quarantine xattr and sends one notification; it does not move the file. Only a malware verdict holds.

## Verdicts

| Verdict | From | Action | Severity |
|---|---|---|---|
| `malware` | A hash IOC in the bundle, a rule with `meta: confidence = "high"`, or an opt-in lookup that names a family | Hold | Critical |
| `gatekeeper-bypass` | The bypass shapes above | Hold | Critical |
| `risky` | Active content that runs on open (macros, PDF JavaScript, `.terminal` commands, `file://` bookmarks) or a lower-confidence rule | Keep or add the xattr, notify | High |
| `quarantine-missing` | A new executable or bundle without the xattr | Add the xattr; record, no notification | Info |
| `clean` | Nothing matched | Nothing; counted, not recorded per file | — |
| `unscanned` | The worker crashed or timed out, the file is over the size cap, or the sandbox could not start | Keep or add the xattr, notify once per file | Warn |

A detonation can raise a verdict, never lower one: a sample that behaves in a VM is not cleared, because malware checks for VMs.

## The scan worker

The resident process watches, classifies by type and xattr, sets the quarantine xattr, and hands each file to a short-lived worker over a pipe. The worker gets an already-open read-only file descriptor, the compiled rules and the hash IOC set, and writes one verdict line back. It never opens a path itself.

macOS profile, applied with `sandbox-exec -p` (deprecated by Apple but still working; a phase-2 check confirms it on the current macOS). A sketch: phase 2 pins the exact read list dyld needs.

```scheme
(version 1)
(deny default)
(allow process-info-pidinfo (target self))
(allow process-exec (literal (param "WORKER")))   ; sandbox-exec starts the worker itself
(allow file-read* (literal (param "WORKER")) (subpath "/usr/lib") (subpath "/System/Library/dyld")
       (subpath "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld"))
(allow file-read-metadata)
(allow sysctl-read)
(deny network*)
(deny process-fork)
(deny file-write*)
```

The only program it may start is the wpantry binary itself, which `sandbox-exec` needs to start the worker; anything that binary started would inherit the same profile. The descriptor for the file and the result pipe are inherited, so the profile grants no path to the file or to the pipe. The worker runs at background QoS (`setpriority(PRIO_DARWIN_PROCESS, 0, PRIO_DARWIN_BG)`), with a 1 GiB address-space limit and a 30 s wall-clock limit for files up to 256 MiB, scaled linearly above.

Linux: `PR_SET_NO_NEW_PRIVS`, then landlock (ABI 1 or later) with no filesystem access granted, and a seccomp filter that kills on `execve`, `execveat`, `socket`, `connect`, `ptrace`, `open`/`openat` with write flags; `SCHED_IDLE` and `ioprio` idle. Where landlock is missing (kernels before 5.13, or disabled), seccomp alone applies and the event says `"sandbox": "seccomp"`.

Archives are read in memory, never unpacked to disk: zip, tar, gzip, bzip2, xz and xar (`.pkg`), nested up to 3 deep, 512 MiB uncompressed and a ratio of 100:1 per member before the member is `unscanned`. Disk images are not mounted by the guard (mounting parses the filesystem in the kernel); a `.dmg` is checked by hash and scanned once the person mounts it.

## Opt-in hash lookups

From the resident process, never the worker, and only the SHA-256: no name, path, size or content. Off until the person turns each source on; answers cached in the cache's `queries` table for 7 days (clean) or forever (malware).

| Source | Key | Asks |
|---|---|---|
| [YARAify](https://yaraify.abuse.ch/api/) | none | `lookup_hash` |
| [CIRCL hashlookup](https://hashlookup.circl.lu/) | none | `/lookup/sha256`; a known-good answer (NSRL and others) is recorded and shown, and does not clear a rule match |
| [MalwareBazaar](https://bazaar.abuse.ch/api/) | the person's own Auth-Key | `get_info` |

By default only executables, scripts, archives and documents with active content are looked up. A hash of a private document is still a fingerprint of having it, which is why documents without active content are never sent.

## The quarantine store

`~/Library/Application Support/wpantry/held.noindex/` on macOS, `$XDG_STATE_HOME/wpantry/held/` on Linux (with `.trackerignore` and `.nomedia`); the directory is 0700. Each held file is stored as `<sha256>` with no extension (so no handler claims it), mode 0400, the quarantine xattr kept, and a sibling `<sha256>.json` with its original path, mode, xattrs, origin (`kMDItemWhereFroms` or `user.xdg.origin.url`), verdict and matches. A move within the volume is a `rename`; across volumes, copy, verify the hash, then unlink. The move checks that the path still names the scanned inode (device, inode, size, mtime) and rescans if not.

## Event object

One per non-clean verdict, as `--json` prints it and as the cache's `events` row keeps it (`kind = "download"`, `detail` without `schema`, `impl`, `version`, `at`). Additive under schema 1.

```json
{"schema": 1, "impl": "rust", "version": "0.4.0", "event": "download", "at": 1793836800.0,
 "path": "/Users/me/Downloads/Setup.app", "sha256": "…", "size": 1048576, "type": "app",
 "origin": {"agent": "Safari", "from": ["https://example.test/setup.zip"]},
 "verdict": "malware", "severity": "critical",
 "matches": [{"source": "yara", "rule": "MacOS_Stealer_AMOS", "bundle": "2026-11-01"}],
 "lookups": [{"source": "yaraify", "answer": "malware", "family": "AMOS"}],
 "actions": ["quarantine-kept", "exec-bit-removed", "held"], "held": "<sha256>",
 "sandbox": "sandbox-exec", "note": "…"}
```

`origin.from` is local metadata the browser wrote; it is recorded locally and, like every other field, never sent to a lookup.

## Handing events to Watchdog

The guard writes events to the cache and nowhere else. A later phase adds `wpantry report --events --after ID --format jsonl` so a local `watchdogd` ([wsentinel](https://github.com/waffuruai/wsentinel)'s Watchdog sidecar) running as a launchd or systemd service can read past a cursor and map each event to its `security_events` stream: `malware` and `gatekeeper-bypass` as `download_held`, `risky` as `download_risky`, `unscanned` as `download_unscanned`. The mapping drops `origin.from` and replaces `path` with its directory class (`Downloads`, `Desktop`, `repo`, `home`) unless the operator's policy keeps paths. pantry opens no socket and sends nothing.
