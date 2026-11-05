//! Programs that listen with Multipath TCP on. CVE-2026-98432 (the Linux
//! kernel's IPv4 TCP handshake use-after-free, kernels 4.4 and later, CVSS
//! 9.8) is reached through an MPTCP listener, and Go 1.24 and later turn
//! MPTCP on for every `net.Listen` and `http.ListenAndServe` on Linux by
//! default, so an unpatched server is exposed by the program it runs, not
//! only by the kernel under it. This reads each repo for a Go module whose
//! `go` line is 1.24 or newer and whose source listens for TCP without
//! opting out (`SetMultipathTCP(false)`, a `godebug multipathtcp=0` line
//! in `go.mod`, a `//go:debug` directive, or `GODEBUG=multipathtcp=0` in
//! a Dockerfile, compose file, Kubernetes manifest, systemd unit or
//! `.env`), and for any language that asks for MPTCP by name
//! (`IPPROTO_MPTCP`, socket2's `Protocol::MPTCP`, `SetMultipathTCP(true)`).
//! Each is a warning with the opt-out as its step, as an unfixed Critical
//! advisory is; [`crate::checks::machine::linux`] judges the kernel itself and
//! `wpantry mitigate CVE-2026-98432` is the host's stopgap. Nothing is ever
//! changed.
//!
//! The `go` line decides, not `toolchain`: Go takes a program's default
//! GODEBUG settings from the main module's `go` directive, so a module on
//! `go 1.22` built with a 1.24 toolchain keeps MPTCP off.

use crate::checks::Scan;
use crate::checks::files::{Contents, Read, Stats, When};
use crate::checks::supply_chain::repos::Repo;
use crate::finding::Finding;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The advisory every exposure here is about.
pub const ID: &str = "CVE-2026-98432";

/// The step for a Go listener: the opt-out, until the kernel is fixed.
pub const GO_FIX: &str = "Until the kernel it runs on has the fix for CVE-2026-98432: set GODEBUG=multipathtcp=0 in the service's environment (Dockerfile ENV, the compose file, the Kubernetes manifest, the systemd unit or .env), add `godebug multipathtcp=0` to go.mod, or call ListenConfig.SetMultipathTCP(false) before listening; the host's stopgap is wpantry mitigate CVE-2026-98432 (docs/public/usage.md#advisories-with-no-fix-yet)";

/// The step for an explicit opt-in.
pub const OPT_IN_FIX: &str = "Until the kernel it runs on has the fix for CVE-2026-98432: take the MPTCP opt-in out, or put it behind a setting that is off by default; the host's stopgap is wpantry mitigate CVE-2026-98432 (docs/public/usage.md#advisories-with-no-fix-yet)";

const UNFIXED: &str = "a remote use-after-free in the IPv4 TCP handshake, kernels 4.4 and later; no fixed kernel released for Ubuntu or RHEL yet";

/// How deep a repo is walked, as the suspicious-code scan walks it.
pub const DEPTH: usize = 6;
/// The most of one file read.
const MAX_FILE: u64 = 1 << 20;
/// The Go release that turned MPTCP on for listeners.
const MPTCP_DEFAULT_SINCE: (u64, u64) = (1, 24);

/// One program exposed through MPTCP.
#[derive(Clone, Debug, PartialEq)]
pub struct Exposure {
    /// Relative to the repo.
    pub file: String,
    pub line: usize,
    /// The module's `go` line (`go 1.24.0`) for a Go listener, "" for an
    /// explicit opt-in.
    pub go: String,
    pub note: String,
    pub fix: &'static str,
}

/// Calls that open a TCP listener in Go. A method call matches whichever
/// server type carries it (`http.Server`, fasthttp, gRPC's `Serve` takes a
/// listener from `net.Listen`).
const GO_LISTENS: &[&str] =
    &["net.Listen(", "net.ListenTCP(", "net.ListenConfig", "ListenAndServe(", "ListenAndServeTLS(", "grpc.NewServer("];

/// Asking for MPTCP by name, in any language.
const OPT_INS: &[&str] = &["IPPROTO_MPTCP", "Protocol::MPTCP", "SetMultipathTCP(true)"];

/// Source where an opt-in is read.
const SOURCE_EXTS: &[&str] =
    &["go", "c", "h", "cc", "cpp", "hpp", "rs", "py", "java", "kt", "zig", "swift", "m", "mm", "cs"];

/// Dependencies and fixtures: not the program.
fn skipped(rel: &str) -> bool {
    let l = format!("/{}", rel.to_ascii_lowercase());
    l.ends_with("_test.go")
        || ["/vendor/", "/testdata/", "/third_party/", "/node_modules/", "/target/", "/dist/", "/build/"]
            .iter()
            .any(|p| l.contains(p))
}

/// `go 1.24.0` → (1, 24): the `go` directive's major and minor.
pub fn go_version(gomod: &str) -> Option<(u64, u64, String)> {
    let line = gomod
        .lines()
        .map(|l| l.split("//").next().unwrap_or("").trim())
        .find(|l| l.strip_prefix("go").is_some_and(|r| r.starts_with(char::is_whitespace)))?;
    let v = line["go".len()..].trim();
    let core: String = v.chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    let (major, minor) = (it.next()??, it.next()??);
    Some((major, minor, line.to_string()))
}

/// Whether `GODEBUG` text turns MPTCP off for listeners: 0 (off) or 3
/// (dialers only).
fn godebug_opts_out(text: &str) -> bool {
    text.contains("multipathtcp=0") || text.contains("multipathtcp=3")
}

/// Files whose environment or directives reach a built program.
fn env_file(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    l.starts_with("dockerfile")
        || l.starts_with("containerfile")
        || l.starts_with(".env")
        || l == "procfile"
        || l == "go.mod"
        || ["yml", "yaml", "service", "env", "toml", "nomad", "hcl"]
            .iter()
            .any(|e| l.rsplit_once('.').map(|(_, x)| x) == Some(e))
}

/// The first listening call in Go source and its line; a `"unix"` listener
/// isn't TCP.
fn go_listen(text: &str) -> Option<(&'static str, usize)> {
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim_start();
        if line.starts_with("//") || line.contains("\"unix") {
            continue;
        }
        if let Some(n) = GO_LISTENS.iter().copied().find(|n| line.contains(n)) {
            return Some((n, i + 1));
        }
    }
    None
}

/// Whether Go source opts its own listeners out.
fn go_opts_out(text: &str) -> bool {
    text.contains("SetMultipathTCP(false)")
        || text.lines().any(|l| l.trim_start().starts_with("//go:debug") && godebug_opts_out(l))
}

/// The first explicit MPTCP opt-in and its line.
fn opt_in(text: &str) -> Option<(&'static str, usize)> {
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim_start();
        if line.starts_with("//") || line.starts_with('#') {
            continue;
        }
        if let Some(n) = OPT_INS.iter().copied().find(|n| line.contains(n)) {
            return Some((n, i + 1));
        }
    }
    None
}

/// Every program under `root` exposed through MPTCP, sorted by file. One
/// job of the files pass ([`crate::checks::files::pass`]).
pub fn scan_repo(root: &Path) -> Vec<Exposure> {
    crate::checks::files::Results::default().mptcp(root)
}

/// A module file (go.mod), an environment file, or a source file.
const GO_MOD: u8 = 0;
const ENV: u8 = 1;
const SOURCE: u8 = 2;

/// The files a repo's check reads: each go.mod, environment file and
/// source file at most [`MAX_FILE`].
#[derive(Debug)]
pub struct Plan {
    pub reads: Vec<Read>,
}

pub fn plan(root: &Path, walk: &[(PathBuf, Vec<String>)], stat: Stats) -> Plan {
    let mut reads = Vec::new();
    for (dir, files) in walk {
        for name in files {
            let path = dir.join(name);
            let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().into_owned();
            if skipped(&rel) {
                continue;
            }
            let role = if name == "go.mod" {
                GO_MOD
            } else if env_file(name) {
                ENV
            } else if SOURCE_EXTS.contains(&name.rsplit_once('.').map(|(_, e)| e).unwrap_or("")) {
                SOURCE
            } else {
                continue;
            };
            if stat(&path).is_some_and(|s| s.file && s.size <= MAX_FILE) {
                reads.push(Read { path, rel, cap: MAX_FILE, role, when: When::Always });
            }
        }
    }
    Plan { reads }
}

/// What one file says: a go.mod's `go` line and whether it opts out; an
/// environment file's opt-out; a source file's opt-in, its Go opt-out and
/// its Go listener.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Facts {
    pub opts_out: bool,
    pub go: Option<(u64, u64, String)>,
    pub opt_in: Option<(&'static str, usize)>,
    pub listen: Option<(&'static str, usize)>,
}

pub fn file(read: &Read, c: &Contents) -> Option<Facts> {
    let text = c.text()?;
    let go_source = read.path.extension().is_some_and(|e| e == "go");
    Some(match read.role {
        GO_MOD => Facts { opts_out: godebug_opts_out(&text), go: go_version(&text), ..Default::default() },
        ENV => Facts { opts_out: godebug_opts_out(&text), ..Default::default() },
        _ => Facts {
            opts_out: go_source && go_opts_out(&text),
            opt_in: opt_in(&text),
            listen: if go_source { go_listen(&text) } else { None },
            go: None,
        },
    })
}

/// The repo's exposures, sorted by file.
pub fn finish(plan: &Plan, files: &[Option<&Option<Facts>>]) -> Vec<Exposure> {
    let read: Vec<(&Read, &Facts)> =
        plan.reads.iter().zip(files).filter_map(|(r, f)| f.and_then(Option::as_ref).map(|f| (r, f))).collect();
    let mut modules: BTreeMap<PathBuf, (u64, u64, String)> = BTreeMap::new();
    let mut env_opt_out = false;
    for (r, f) in read.iter().filter(|(r, _)| r.role != SOURCE) {
        env_opt_out |= f.opts_out;
        if let (Some(go), Some(dir)) = (&f.go, r.path.parent()) {
            modules.insert(dir.to_path_buf(), go.clone());
        }
    }
    // Which module a Go file belongs to: the nearest go.mod above it.
    let module_of = |path: &Path| -> Option<(&PathBuf, &(u64, u64, String))> {
        modules.iter().filter(|(dir, _)| path.starts_with(dir)).max_by_key(|(dir, _)| dir.as_os_str().len())
    };
    let sources: Vec<&(&Read, &Facts)> = read.iter().filter(|(r, _)| r.role == SOURCE).collect();
    // A module opts out when any of its own files does (one helper may wrap every listener).
    let mut module_opt_out: BTreeMap<&PathBuf, bool> = BTreeMap::new();
    for (r, f) in &sources {
        if f.opts_out
            && let Some((dir, _)) = module_of(&r.path)
        {
            module_opt_out.insert(dir, true);
        }
    }
    let mut out = Vec::new();
    for (r, f) in &sources {
        if let Some((needle, line)) = f.opt_in {
            out.push(Exposure {
                file: r.rel.clone(),
                line,
                go: String::new(),
                note: format!(
                    "asks for Multipath TCP by name ({needle}): a listener on it reaches CVE-2026-98432 ({UNFIXED})"
                ),
                fix: OPT_IN_FIX,
            });
            continue;
        }
        if env_opt_out || r.path.extension().is_none_or(|e| e != "go") {
            continue;
        }
        let Some((dir, (major, minor, go_line))) = module_of(&r.path) else { continue };
        if (*major, *minor) < MPTCP_DEFAULT_SINCE || module_opt_out.contains_key(dir) {
            continue;
        }
        let Some((needle, line)) = f.listen else { continue };
        out.push(Exposure {
            file: r.rel.clone(),
            line,
            go: go_line.clone(),
            note: format!(
                "listens for TCP ({needle}) in a module on `{go_line}`: Go 1.24 and later listen with Multipath TCP on Linux by default, which reaches CVE-2026-98432 ({UNFIXED})"
            ),
            fix: GO_FIX,
        });
    }
    out.sort_by(|a, b| a.file.cmp(&b.file));
    out
}

/// Programs that listen with Multipath TCP on (Go 1.24 and later by
/// default, or an explicit opt-in): CVE-2026-98432 is reachable through
/// the listener until the kernel under it is fixed, so each warns with the
/// opt-out as its step, as an unfixed Critical advisory does, and counts
/// as unfixed. Never a failure: the program is right, the kernel isn't.
pub fn mptcp_listeners(scan: &mut Scan, repos: &[Repo]) {
    if repos.is_empty() {
        return;
    }
    scan.status("Looking for programs that listen with Multipath TCP on");
    let results = scan.read_files();
    let found: Vec<Vec<Exposure>> = repos.iter().map(|(_, root)| results.mptcp(root)).collect();
    let kev = scan.kev.contains(ID);
    for ((name, _), hits) in repos.iter().zip(found) {
        scan.count("repos checked for programs listening with MPTCP on", 1);
        for h in hits {
            scan.unfixed += 1;
            scan.add(Finding {
                kind: "project".into(),
                component: format!("{name}/{}", h.file),
                version: h.go,
                location: format!("line {}", h.line),
                vuln_id: ID.into(),
                status: "warn".into(),
                kev,
                severity: "CRITICAL".into(),
                note: h.note,
                fix_cmd: h.fix.into(),
                ..Default::default()
            });
        }
    }
}

#[cfg(test)]
#[path = "mptcp_tests.rs"]
mod tests;
