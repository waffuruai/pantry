use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};

/// A fresh folder under the system temp dir, removed on drop.
pub(super) struct Scratch(pub(super) PathBuf);

impl Scratch {
    pub(super) fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "wpantry-setup-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Encode records the way `desktop/release/setup.py payload` does.
pub(super) fn raw(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (path, body, executable) in entries {
        out.extend_from_slice(&(path.len() as u16).to_le_bytes());
        out.extend_from_slice(&(body.len() as u32).to_le_bytes());
        out.push(u8::from(*executable));
        out.extend_from_slice(path.as_bytes());
        out.extend_from_slice(body);
    }
    out
}

pub(super) fn payload(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(&raw(entries), 6)
}

pub(super) fn app_payload(body: &[u8]) -> Vec<u8> {
    payload(&[(APP, body, true), (SCANNER, b"scanner", true)])
}

pub(super) fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

// Oracle: with `setup.lock` held by another holder, Setup gets
// SetupRunning (run() then prints SETUP_RUNNING) and installs nothing;
// with `window.lock` held, the existing open-Pantry rules apply.
// Known-bad: the old code returned Ok(()) with no message.
#[test]
fn a_second_setup_says_setup_is_running() {
    let scratch = Scratch::new();
    let state = scratch.0.join("state");
    let destination = scratch.0.join("installed");
    let held = instance::try_lock(&state, instance::SETUP_LOCK)
        .unwrap()
        .unwrap();
    for mode in [Mode::Install, Mode::InstallOnly, Mode::Uninstall] {
        assert_eq!(
            take_locks(&state, &destination, mode, "1.0.0")
                .unwrap()
                .err(),
            Some(Blocked::SetupRunning)
        );
    }
    assert!(SETUP_RUNNING.contains("already running"));
    drop(held);
    let window = instance::try_lock(&state, instance::WINDOW_LOCK)
        .unwrap()
        .unwrap();
    assert_eq!(
        take_locks(&state, &destination, Mode::InstallOnly, "1.0.0")
            .unwrap()
            .err(),
        Some(Blocked::Refuse(RUNNING))
    );
    drop(window);
    assert!(
        take_locks(&state, &destination, Mode::Install, "1.0.0")
            .unwrap()
            .is_ok()
    );
    assert!(!destination.exists());
}

// Oracle: errno / Windows error tables. Busy or locked files
// (EBUSY 16, ETXTBSY 26, Windows 32/33) read as in use; EPERM 1 and
// EACCES 13 read as no permission and name the folder; Windows 5 gets
// its combined sentence; the system's text stays as detail; Setup's own
// messages pass through. Known-bad: the old code called every
// permission error "Pantry is in use".
#[test]
fn errors_read_plainly() {
    let folder = Path::new("/somewhere/Pantry");
    assert_eq!(explain(&io::Error::other(RUNNING), Some(folder)), RUNNING);
    let busy = explain(&io::Error::from(io::ErrorKind::ResourceBusy), None);
    assert!(
        busy.starts_with(IN_USE) && busy.contains("Details: "),
        "{busy}"
    );
    #[cfg(unix)]
    {
        for code in [16, 26] {
            let text = explain(&io::Error::from_raw_os_error(code), Some(folder));
            assert!(text.starts_with(IN_USE), "{code}: {text}");
        }
        for code in [1, 13] {
            let error = io::Error::from_raw_os_error(code);
            let text = explain(&error, Some(folder));
            assert!(
                text.starts_with(NO_PERMISSION)
                    && text.contains("/somewhere/Pantry")
                    && text.ends_with(&error.to_string())
                    && !text.contains(IN_USE),
                "{code}: {text}"
            );
        }
    }
    #[cfg(windows)]
    {
        for code in [32, 33] {
            assert!(explain(&io::Error::from_raw_os_error(code), None).starts_with(IN_USE));
        }
        assert!(explain(&io::Error::from_raw_os_error(5), None).starts_with(WINDOWS_DENIED));
    }
}
