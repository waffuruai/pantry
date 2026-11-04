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

use crate::utils::walk::walk;
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
const WALK_DEPTH: usize = 6;
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

fn read(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    (meta.is_file() && meta.len() <= MAX_FILE).then(|| crate::utils::files::read_capped(path, MAX_FILE).ok())?
}

/// Every program under `root` exposed through MPTCP, sorted by file.
pub fn scan_repo(root: &Path) -> Vec<Exposure> {
    let mut modules: BTreeMap<PathBuf, (u64, u64, String)> = BTreeMap::new();
    let mut sources: Vec<(String, PathBuf)> = Vec::new();
    let mut env_opt_out = false;
    for (dir, files) in walk(root, WALK_DEPTH) {
        for name in files {
            let path = dir.join(&name);
            let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().into_owned();
            if skipped(&rel) {
                continue;
            }
            if name == "go.mod" {
                if let Some(text) = read(&path) {
                    if godebug_opts_out(&text) {
                        env_opt_out = true;
                    }
                    if let Some((major, minor, line)) = go_version(&text) {
                        modules.insert(dir.clone(), (major, minor, line));
                    }
                }
                continue;
            }
            if env_file(&name) {
                if read(&path).is_some_and(|t| godebug_opts_out(&t)) {
                    env_opt_out = true;
                }
                continue;
            }
            let ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
            if SOURCE_EXTS.contains(&ext) {
                sources.push((rel, path));
            }
        }
    }
    // Which module a Go file belongs to: the nearest go.mod above it.
    let module_of = |path: &Path| -> Option<(&PathBuf, &(u64, u64, String))> {
        modules.iter().filter(|(dir, _)| path.starts_with(dir)).max_by_key(|(dir, _)| dir.as_os_str().len())
    };
    // A module opts out when any of its own files does (one helper may wrap every listener).
    let mut module_opt_out: BTreeMap<&PathBuf, bool> = BTreeMap::new();
    let texts: Vec<(String, PathBuf, String)> =
        sources.into_iter().filter_map(|(rel, path)| read(&path).map(|t| (rel, path, t))).collect();
    for (_, path, text) in &texts {
        if path.extension().is_some_and(|e| e == "go")
            && go_opts_out(text)
            && let Some((dir, _)) = module_of(path)
        {
            module_opt_out.insert(dir, true);
        }
    }
    let mut out = Vec::new();
    for (rel, path, text) in &texts {
        if let Some((needle, line)) = opt_in(text) {
            out.push(Exposure {
                file: rel.clone(),
                line,
                go: String::new(),
                note: format!(
                    "asks for Multipath TCP by name ({needle}): a listener on it reaches CVE-2026-98432 ({UNFIXED})"
                ),
                fix: OPT_IN_FIX,
            });
            continue;
        }
        if env_opt_out || path.extension().is_none_or(|e| e != "go") {
            continue;
        }
        let Some((dir, (major, minor, go_line))) = module_of(path) else { continue };
        if (*major, *minor) < MPTCP_DEFAULT_SINCE || module_opt_out.contains_key(dir) {
            continue;
        }
        let Some((needle, line)) = go_listen(text) else { continue };
        out.push(Exposure {
            file: rel.clone(),
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

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: &str = "package main\n\nimport (\n\t\"net\"\n\t\"net/http\"\n)\n\nfunc main() {\n\t// net.Listen in a comment doesn't count\n\tln, _ := net.Listen(\"tcp\", \":8080\")\n\thttp.Serve(ln, nil)\n}\n";

    fn repo(files: &[(&str, &str)]) -> crate::utils::temp::TempDir {
        let d = crate::utils::temp::TempDir::new("mptcp").unwrap();
        for (name, text) in files {
            let p = d.path().join(name);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, text).unwrap();
        }
        d
    }

    #[test]
    fn go_version_reads_the_go_line_not_the_toolchain() {
        assert_eq!(go_version("module x\n\ngo 1.24.0\n\ntoolchain go1.25.1\n"), Some((1, 24, "go 1.24.0".into())));
        assert_eq!(go_version("go 1.22 // keeps old defaults\ntoolchain go1.24.1\n"), Some((1, 22, "go 1.22".into())));
        assert_eq!(go_version("go 1.24rc1\n"), Some((1, 24, "go 1.24rc1".into())));
        assert_eq!(go_version("module x\ngodebug multipathtcp=0\n"), None, "a godebug line isn't the go line");
        assert_eq!(go_version("go\n"), None);
    }

    #[test]
    fn a_go_1_24_server_warns_until_it_opts_out() {
        let d = repo(&[("go.mod", "module x\n\ngo 1.24.0\n"), ("main.go", SERVER)]);
        let got = scan_repo(d.path());
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!((got[0].file.as_str(), got[0].line, got[0].go.as_str()), ("main.go", 10, "go 1.24.0"));
        assert!(got[0].note.contains("net.Listen(") && got[0].note.contains("CVE-2026-98432"), "{}", got[0].note);
        assert_eq!(got[0].fix, GO_FIX);

        let code = repo(&[
            ("go.mod", "module x\n\ngo 1.24.0\n"),
            ("main.go", SERVER),
            (
                "listen.go",
                "package main\nimport \"net\"\nfunc ln() { var lc net.ListenConfig; lc.SetMultipathTCP(false) }\n",
            ),
        ]);
        assert!(scan_repo(code.path()).is_empty(), "SetMultipathTCP(false) anywhere in the module");

        let docker = repo(&[
            ("go.mod", "module x\n\ngo 1.24.0\n"),
            ("cmd/api/main.go", SERVER),
            ("Dockerfile", "FROM golang:1.24\nENV GODEBUG=multipathtcp=0\n"),
        ]);
        assert!(scan_repo(docker.path()).is_empty(), "the Dockerfile's environment");

        let compose = repo(&[
            ("go.mod", "module x\n\ngo 1.24.0\n"),
            ("main.go", SERVER),
            ("deploy/api.yaml", "env:\n  - name: GODEBUG\n    value: multipathtcp=0\n"),
        ]);
        assert!(scan_repo(compose.path()).is_empty(), "a manifest's environment");

        let gomod = repo(&[("go.mod", "module x\n\ngo 1.24.0\n\ngodebug multipathtcp=0\n"), ("main.go", SERVER)]);
        assert!(scan_repo(gomod.path()).is_empty(), "go.mod's own godebug line");

        let directive = repo(&[
            ("go.mod", "module x\n\ngo 1.24.0\n"),
            ("main.go", &format!("//go:debug multipathtcp=0\n{SERVER}")),
        ]);
        assert!(scan_repo(directive.path()).is_empty(), "the //go:debug directive");
    }

    #[test]
    fn older_go_non_listeners_tests_and_vendor_are_quiet() {
        let old = repo(&[("go.mod", "module x\n\ngo 1.23\n\ntoolchain go1.24.1\n"), ("main.go", SERVER)]);
        assert!(scan_repo(old.path()).is_empty(), "the go line keeps MPTCP off whatever the toolchain");
        let client = repo(&[
            ("go.mod", "module x\n\ngo 1.24.0\n"),
            ("main.go", "package main\nimport \"net/http\"\nfunc main() { http.Get(\"https://example.com\") }\n"),
        ]);
        assert!(scan_repo(client.path()).is_empty(), "no listener");
        let unix = repo(&[
            ("go.mod", "module x\n\ngo 1.24.0\n"),
            ("main.go", "package main\nimport \"net\"\nfunc main() { net.Listen(\"unix\", \"/run/x.sock\") }\n"),
        ]);
        assert!(scan_repo(unix.path()).is_empty(), "a unix socket isn't TCP");
        let quiet = repo(&[
            ("go.mod", "module x\n\ngo 1.24.0\n"),
            ("main_test.go", SERVER),
            ("vendor/dep/server.go", SERVER),
            ("testdata/server.go", SERVER),
        ]);
        assert!(scan_repo(quiet.path()).is_empty(), "tests, vendor and fixtures");
        let no_mod = repo(&[("main.go", SERVER)]);
        assert!(scan_repo(no_mod.path()).is_empty(), "no go.mod: no go line to judge by");
    }

    #[test]
    fn nested_modules_are_judged_by_their_own_go_line() {
        let d = repo(&[
            ("go.mod", "module x\n\ngo 1.22\n"),
            ("main.go", SERVER),
            ("svc/go.mod", "module x/svc\n\ngo 1.24\n"),
            ("svc/main.go", SERVER),
        ]);
        let got = scan_repo(d.path());
        assert_eq!(got.iter().map(|e| e.file.as_str()).collect::<Vec<_>>(), ["svc/main.go"], "{got:?}");
    }

    #[test]
    fn an_explicit_opt_in_warns_in_any_language() {
        let d = repo(&[
            ("go.mod", "module x\n\ngo 1.22\n"),
            ("srv.c", "#include <sys/socket.h>\nint s = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);\n"),
            (
                "src/main.rs",
                "use socket2::{Protocol, Socket};\nlet s = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::MPTCP))?;\n",
            ),
            (
                "serve.py",
                "import socket\n# socket.IPPROTO_MPTCP in a comment\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_MPTCP)\n",
            ),
            (
                "ln.go",
                "package main\nimport \"net\"\nfunc main() { var lc net.ListenConfig; lc.SetMultipathTCP(true); lc.Listen(nil, \"tcp\", \":80\") }\n",
            ),
            ("Dockerfile", "ENV GODEBUG=multipathtcp=0\n"),
        ]);
        let got = scan_repo(d.path());
        assert_eq!(
            got.iter().map(|e| (e.file.as_str(), e.line)).collect::<Vec<_>>(),
            [("ln.go", 3), ("serve.py", 3), ("src/main.rs", 2), ("srv.c", 2)],
            "an opt-in counts whatever the go line or environment says: {got:?}"
        );
        assert!(got.iter().all(|e| e.go.is_empty() && e.fix == OPT_IN_FIX && e.note.contains("by name")));
    }
}
