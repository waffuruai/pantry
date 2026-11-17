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

    let directive =
        repo(&[("go.mod", "module x\n\ngo 1.24.0\n"), ("main.go", &format!("//go:debug multipathtcp=0\n{SERVER}"))]);
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
