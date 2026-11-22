use super::*;

pub(super) fn scratch(name: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("pantry-desktop-test-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn locate_prefers_flag_then_sibling_and_uses_path_only_in_debug() {
    let root = scratch("locate");
    let name = format!("wpantry{}", std::env::consts::EXE_SUFFIX);
    let app_dir = root.join("app");
    let path_dir = root.join("bin");
    std::fs::create_dir_all(&app_dir).unwrap();
    std::fs::create_dir_all(&path_dir).unwrap();
    let exe = app_dir.join("wpantry-desktop");
    let on_path = path_dir.join(&name);
    std::fs::write(&on_path, b"").unwrap();
    let path_var = std::env::join_paths([&path_dir]).unwrap();

    // No sibling: release builds must not take the PATH copy.
    let (path, found) = find(None, Some(&exe), false, Some(&path_var));
    assert_eq!((path, found), (app_dir.join(&name), false));
    // Debug builds may.
    let (path, found) = find(None, Some(&exe), true, Some(&path_var));
    assert_eq!((path, found), (on_path.clone(), true));
    // The sibling wins over PATH in every build.
    std::fs::write(app_dir.join(&name), b"").unwrap();
    let (path, found) = find(None, Some(&exe), true, Some(&path_var));
    assert_eq!((path, found), (app_dir.join(&name), true));
    // An explicit flag wins over both.
    let (path, found) = find(Some(on_path.clone()), Some(&exe), false, None);
    assert_eq!((path, found), (on_path, true));
    let _ = std::fs::remove_dir_all(root);
}

/// A finished child's output, for the parsing checks.
pub(super) fn output(code: i32, stdout: &str, stderr: &str) -> Output {
    #[cfg(unix)]
    let status = std::os::unix::process::ExitStatusExt::from_raw(code << 8);
    #[cfg(windows)]
    let status = std::os::windows::process::ExitStatusExt::from_raw(code as u32);
    Output {
        status,
        stdout: stdout.as_bytes().to_vec(),
        stderr: stderr.as_bytes().to_vec(),
    }
}

#[test]
fn missing_folders_names_only_folders_that_are_gone() {
    let here = std::env::temp_dir();
    let gone = here.join("pantry-no-such-folder-for-this-test");
    let scope = format!("repos:{},{}+licenses", here.display(), gone.display());
    assert_eq!(missing_folders(&scope), [gone.display().to_string()]);
    assert!(missing_folders("machine:~").is_empty());
    assert!(missing_folders("machine:~;no-personal-files").is_empty());
}

#[test]
fn scope_round_trips_to_a_scan() {
    let here = std::env::temp_dir().to_string_lossy().into_owned();
    assert_eq!(
        ScanRequest::for_scope("machine:~;no-personal-files", true),
        Some(ScanRequest {
            machine: true,
            paths: vec![],
            include_personal_files: false,
            offline: true
        })
    );
    assert!(
        ScanRequest::for_scope("machine:~", false)
            .unwrap()
            .include_personal_files
    );
    assert_eq!(
        ScanRequest::for_scope(&format!("repos:{here}"), false)
            .unwrap()
            .paths,
        vec![here.clone()]
    );
    assert_eq!(ScanRequest::for_scope("repos:~+licenses", false), None);
    assert_eq!(ScanRequest::for_scope("repos:/no/such/dir", false), None);
    assert_eq!(ScanRequest::for_scope("nonsense", false), None);
}
