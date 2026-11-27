use super::*;
use crate::utils::temp::TempDir;

fn env(home: &Path, os: &'static str) -> Env {
    Env { home: home.to_path_buf(), os, user_base: None, appdata: None, developer_dir: None }
}

fn touch(p: &Path) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, "").unwrap();
}

fn s(p: &Path) -> String {
    p.display().to_string()
}

/// Oracle: CPython's `site` (3.9 to 3.14): a macOS framework build uses
/// `~/Library/Python/X.Y/lib/python/site-packages`, other POSIX builds
/// `~/.local/lib/pythonX.Y[t]/site-packages`; the marker in the stdlib
/// is what `managed` reports.
#[cfg(unix)]
#[test]
fn the_layout_gives_line_user_site_and_marker() {
    let d = TempDir::new("layout").unwrap();
    let fw = d.path().join("Python.framework/Versions/3.12/bin/python3");
    touch(&fw);
    touch(&d.path().join("Python.framework/Versions/3.12/lib/python3.12/EXTERNALLY-MANAGED"));
    let home = d.path().join("home");
    let got = read(&s(&fw), &s(&fw), &env(&home, "macos"));
    let want = home.join("Library/Python/3.12/lib/python/site-packages");
    assert_eq!(got, Layout::Read { runs: s(&fw), line: "3.12".into(), user: Some(s(&want)), managed: true });
    let deb = d.path().join("usr/bin/python3.13t");
    touch(&deb);
    let got = read(&s(&deb), &s(&deb), &env(&home, "linux"));
    let want = home.join(".local/lib/python3.13t/site-packages");
    assert_eq!(got, Layout::Read { runs: s(&deb), line: "3.13".into(), user: Some(s(&want)), managed: false });
    // `python3` alone: the one `lib/python3.N` with an `os.py`.
    let plain = d.path().join("opt/bin/python3");
    touch(&plain);
    touch(&d.path().join("opt/lib/python3.11/os.py"));
    assert!(matches!(read(&s(&plain), &s(&plain), &env(&home, "linux")), Layout::Read { line, .. } if line == "3.11"));
    // PYTHONUSERBASE moves it, as in `site`.
    let mut moved = env(&home, "linux");
    moved.user_base = Some(d.path().join("base"));
    let Layout::Read { user, .. } = read(&s(&deb), &s(&deb), &moved) else { panic!() };
    assert_eq!(user, Some(s(&d.path().join("base/lib/python3.13t/site-packages"))));
}

/// Oracle: `%APPDATA%\Python\PythonXY\site-packages`, the version from
/// `python3XY.dll` beside `python.exe`.
#[test]
fn a_windows_layout_reads_the_dll_and_appdata() {
    let d = TempDir::new("winlayout").unwrap();
    let exe = d.path().join("Python312/python.exe");
    touch(&exe);
    touch(&d.path().join("Python312/python312.dll"));
    touch(&d.path().join("Python312/python3.dll"));
    let mut e = env(&d.path().join("home"), "windows");
    e.appdata = Some(d.path().join("Roaming"));
    let Layout::Read { line, user, .. } = read(&s(&exe), &s(&exe), &e) else { panic!() };
    assert_eq!(line, "3.12");
    // Native separators throughout, as `site` builds it with os.path.join.
    assert_eq!(user, Some(s(&d.path().join("Roaming").join("Python").join("Python312").join("site-packages"))));
}

/// Risk: Apple's stub is reported as an unknown Python on every Mac
/// without the developer tools, or a Mac with them loses its user site.
/// Oracle: no developer folder Python is `Absent`; with one, the layout of
/// the framework Python it starts.
#[cfg(unix)]
#[test]
fn apples_stub_is_read_through_the_developer_folder() {
    let d = TempDir::new("stub").unwrap();
    let mut e = env(&d.path().join("home"), "macos");
    assert_eq!(read("/usr/bin/python3", "/usr/bin/python3", &e), Layout::Absent);
    e.developer_dir = Some(d.path().join("CommandLineTools"));
    assert_eq!(read("/usr/bin/python3", "/usr/bin/python3", &e), Layout::Absent);
    let real = d.path().join("CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9");
    touch(&real);
    let link = d.path().join("CommandLineTools/usr/bin/python3");
    std::fs::create_dir_all(link.parent().unwrap()).unwrap();
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let Layout::Read { line, user, .. } = read("/usr/bin/python3", "/usr/bin/python3", &e) else { panic!() };
    assert_eq!(line, "3.9");
    assert_eq!(user, Some(s(&d.path().join("home/Library/Python/3.9/lib/python/site-packages"))));
}

/// Oracle: a venv without system site-packages reads no user site (pipx's).
#[test]
fn a_venv_reads_no_user_site() {
    let d = TempDir::new("venvlayout").unwrap();
    let exe = d.path().join("venv/bin/python");
    touch(&exe);
    std::fs::write(d.path().join("venv/pyvenv.cfg"), "home = /x/bin\nversion_info = 3.12.4\n").unwrap();
    let got = read(&s(&exe), &s(&exe), &env(d.path(), "linux"));
    assert_eq!(got, Layout::Read { runs: s(&exe), line: "3.12".into(), user: None, managed: false });
}

/// Oracle: no file name, framework, keg or single stdlib to go by.
#[test]
fn an_unreadable_layout_is_unknown() {
    let d = TempDir::new("nolayout").unwrap();
    let exe = d.path().join("x/python");
    touch(&exe);
    assert!(matches!(read(&s(&exe), &s(&exe), &env(d.path(), "linux")), Layout::Unknown(_)));
}
