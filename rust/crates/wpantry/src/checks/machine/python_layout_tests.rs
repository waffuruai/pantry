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

fn put(p: &Path, text: &str) {
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

/// Oracle: CPython's `Include/patchlevel.h` defines `PY_VERSION` as the
/// string `platform.python_version()` reports; it is installed under
/// `include/pythonX.Y[t]` on POSIX and as `include\patchlevel.h` on Windows.
#[test]
fn the_full_version_comes_from_patchlevel_h() {
    let d = TempDir::new("fullversion").unwrap();
    let exe = d.path().join("opt/bin/python3.13t");
    touch(&exe);
    put(&d.path().join("opt/include/python3.13t/patchlevel.h"), "#define PY_VERSION        \"3.13.0rc1\"\n");
    assert_eq!(version_of(&s(&exe), "linux"), Ok("3.13.0rc1".into()));
    // `python3` alone: the one release line's headers under the prefix.
    let plain = d.path().join("p/bin/python3");
    touch(&plain);
    put(&d.path().join("p/include/python3.11/patchlevel.h"), "#define PY_VERSION \"3.11.9\"\n");
    assert_eq!(version_of(&s(&plain), "linux"), Ok("3.11.9".into()));
    put(&d.path().join("p/include/python3.12/patchlevel.h"), "#define PY_VERSION \"3.12.4\"\n");
    assert!(version_of(&s(&plain), "linux").is_err(), "two release lines name no one version");
    // Windows: the folder of the interpreter is the prefix.
    let win = d.path().join("Python312/python.exe");
    touch(&win);
    put(&d.path().join("Python312/include/patchlevel.h"), "#define PY_VERSION \"3.12.4\"\n");
    assert_eq!(version_of(&s(&win), "windows"), Ok("3.12.4".into()));
}

/// Oracle: the python.org framework's `Resources/Info.plist` carries the
/// full version as `CFBundleShortVersionString`; conda records the package
/// it installed in `conda-meta/<name>-<version>-<build>.json`; uv names a
/// managed install `<impl>-<version>-<os>-<arch>-<libc>`.
#[test]
fn a_framework_conda_or_uv_install_says_its_version_without_headers() {
    let d = TempDir::new("fullversion").unwrap();
    let fw = d.path().join("Python.framework/Versions/3.12/bin/python3.12");
    touch(&fw);
    let plist = d.path().join("Python.framework/Versions/3.12/Resources/Info.plist");
    put(&plist, "<dict>\n\t<key>CFBundleShortVersionString</key>\n\t<string>3.12.4</string>\n</dict>\n");
    assert_eq!(version_of(&s(&fw), "macos"), Ok("3.12.4".into()));
    assert!(version_of(&s(&fw), "linux").is_err(), "a plist is a macOS framework's only");
    let conda = d.path().join("miniforge3/bin/python3");
    touch(&conda);
    put(
        &d.path().join("miniforge3/conda-meta/python-dateutil-2.9.0-pyhd8ed1ab_0.json"),
        r#"{"name": "python-dateutil", "version": "2.9.0"}"#,
    );
    put(
        &d.path().join("miniforge3/conda-meta/python-3.12.4-h99e199e_0.json"),
        r#"{"name": "python", "version": "3.12.4"}"#,
    );
    assert_eq!(version_of(&s(&conda), "linux"), Ok("3.12.4".into()));
    let uv = d.path().join("uv/python/cpython-3.12.4+freethreaded-linux-x86_64-gnu/bin/python3.12");
    touch(&uv);
    assert_eq!(version_of(&s(&uv), "linux"), Ok("3.12.4".into()));
    // The same name outside uv's folder of installs is not relied on.
    let lookalike = d.path().join("opt/cpython-3.12.4-linux-x86_64-gnu/bin/python3.12");
    touch(&lookalike);
    assert!(version_of(&s(&lookalike), "linux").is_err());
}

/// Oracle: two files of one install that name different versions, or a
/// version of another release line than the layout's, say no one version.
#[test]
fn files_that_disagree_give_no_version() {
    let d = TempDir::new("fullversion").unwrap();
    let uv = d.path().join("uv/python/cpython-3.12.4-linux-x86_64-gnu/bin/python3.12");
    touch(&uv);
    put(
        &d.path().join("uv/python/cpython-3.12.4-linux-x86_64-gnu/include/python3.12/patchlevel.h"),
        "#define PY_VERSION \"3.12.5\"\n",
    );
    let why = version_of(&s(&uv), "linux").unwrap_err();
    assert!(why.contains("3.12.5") && why.contains("3.12.4"), "{why}");
    let odd = d.path().join("o/bin/python3.12");
    touch(&odd);
    put(&d.path().join("o/include/python3.12/patchlevel.h"), "#define PY_VERSION \"3.11.2\"\n");
    assert!(version_of(&s(&odd), "linux").is_err());
    put(&d.path().join("o/include/python3.12/patchlevel.h"), "#define PY_VERSION \"three\"\n");
    assert!(version_of(&s(&odd), "linux").is_err());
    let bare = d.path().join("b/bin/python3.12");
    touch(&bare);
    assert!(version_of(&s(&bare), "linux").unwrap_err().contains("patchlevel.h"));
}
