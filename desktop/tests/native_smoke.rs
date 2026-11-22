//! The native Linux renderer maps one Pantry window under Xvfb, and a second
//! launch reuses it. This opens a real window, so it is Linux-only and
//! `#[ignore]`d; CI runs it inside a virtual display:
//!
//! ```text
//! (cd rust && cargo build -p wpantry-cli)
//! cd desktop && xvfb-run -a cargo test --test native_smoke -- --ignored
//! ```
//!
//! The scanner is `PANTRY_E2E_SCANNER` when set (it must exist), else
//! `../rust/target/debug/wpantry`.

#[cfg(target_os = "linux")]
#[test]
#[ignore = "opens a real window; run under xvfb-run"]
fn native_window_opens_once() {
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    let scanner = match std::env::var_os("PANTRY_E2E_SCANNER") {
        Some(path) => std::path::absolute(path).unwrap(),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../rust/target/debug/wpantry"),
    };
    assert!(scanner.is_file(), "no scanner at {}", scanner.display());
    let app = PathBuf::from(env!("CARGO_BIN_EXE_wpantry-desktop"));
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
        "pantry-native-smoke-{}-{nanos}",
        std::process::id()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let launch = || {
        let mut command = Command::new(&app);
        command
            .arg("--scanner")
            .arg(&scanner)
            .env("HOME", &root)
            .env("WPANTRY_DB", root.join("pantry.db"))
            .env("WPANTRY_DESKTOP_HOME", &root)
            .env("XDG_STATE_HOME", root.join("state"))
            .env("XDG_CONFIG_HOME", root.join("config"))
            .env("LIBGL_ALWAYS_SOFTWARE", "1");
        command
    };
    let mut process = launch().spawn().expect("start Pantry");
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = process.try_wait().unwrap() {
                panic!("Pantry quit with status {status}.");
            }
            let info = Command::new("xwininfo")
                .args(["-name", "Pantry"])
                .stderr(Stdio::null())
                .output();
            if info.is_ok_and(|o| {
                o.status.success()
                    && String::from_utf8_lossy(&o.stdout).contains("Map State: IsViewable")
            }) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "The Pantry window never became viewable."
            );
            std::thread::sleep(Duration::from_millis(100));
        }
        // A second launch hands over to the open window and exits.
        let mut second = launch().spawn().expect("start Pantry again");
        let deadline = Instant::now() + Duration::from_secs(5);
        let status = loop {
            if let Some(status) = second.try_wait().unwrap() {
                break status;
            }
            if Instant::now() > deadline {
                let _ = second.kill();
                panic!("the second launch did not exit");
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        assert!(status.success(), "the second launch exited with {status}");
        assert_eq!(
            std::fs::read(root.join("state").join("activate")).unwrap(),
            b"\n"
        );
        assert!(
            process.try_wait().unwrap().is_none(),
            "the first window closed"
        );
    }));
    if process.try_wait().unwrap().is_none() {
        // terminate(), as the Python check did: SIGTERM, then wait.
        let _ = Command::new("kill").arg(process.id().to_string()).status();
        let deadline = Instant::now() + Duration::from_secs(10);
        while process.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(50));
        }
        if process.try_wait().unwrap().is_none() {
            let _ = process.kill();
            let _ = process.wait();
        }
    }
    match result {
        Ok(()) => {
            let _ = std::fs::remove_dir_all(&root);
            println!("Pantry opened one native Linux window and reused it on a second launch.");
        }
        Err(panic) => {
            eprintln!("Kept the test folder {}", root.display());
            std::panic::resume_unwind(panic);
        }
    }
}
