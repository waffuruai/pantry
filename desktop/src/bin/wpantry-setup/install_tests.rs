use super::*;
use crate::tests::{Scratch, app_payload, entries, payload, raw};
use crate::{APP, MARKER, NEWER_INSTALLED, PAYLOAD_LIMIT, PREVIOUS, SCANNER, explain};

// Oracle: the semver triple grammar. Exactly three dot-separated u32s.
#[test]
fn version_accepts_only_three_numbers() {
    assert_eq!(version("0.6.0"), Some([0, 6, 0]));
    assert_eq!(version(" 1.2.3\n"), Some([1, 2, 3]));
    for bad in ["", "1.2", "1.2.3.4", "a.b.c", "1.2.-3", "1..3", "v1.2.3"] {
        assert_eq!(version(bad), None, "{bad:?}");
    }
    // Numeric, not lexical, order: the downgrade guard depends on it.
    assert!(version("0.10.0") > version("0.9.9"));
}

// Oracle: the payload round-trips byte for byte, with the exec bit set
// only where the record asks for it.
#[test]
fn unpack_writes_every_record() {
    let scratch = Scratch::new();
    let data = payload(&[("a/b.txt", b"hello", false), ("run", b"#!", true)]);
    unpack(&data, &scratch.0, PAYLOAD_LIMIT).unwrap();
    assert_eq!(fs::read(scratch.0.join("a/b.txt")).unwrap(), b"hello");
    assert_eq!(fs::read(scratch.0.join("run")).unwrap(), b"#!");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = |name: &str| {
            fs::metadata(scratch.0.join(name))
                .unwrap()
                .permissions()
                .mode()
        };
        assert_eq!(mode("run") & 0o111, 0o111);
        assert_eq!(mode("a/b.txt") & 0o111, 0);
    }
}

// Oracle: no entry may escape the stage. Known-bad cases: parent
// components, absolute paths, a leading `.`, an empty path. Nothing may
// be written beside the stage.
#[test]
fn unpack_rejects_paths_outside_the_stage() {
    let scratch = Scratch::new();
    let stage = scratch.0.join("stage");
    fs::create_dir(&stage).unwrap();
    let absolute = scratch.0.join("absolute.txt");
    let absolute = absolute.to_str().unwrap();
    for bad in ["../escaped.txt", "a/../../escaped.txt", absolute, "./x", ""] {
        let error = unpack(&payload(&[(bad, b"x", false)]), &stage, PAYLOAD_LIMIT).unwrap_err();
        assert!(
            error.to_string().contains("invalid file path"),
            "{bad:?}: {error}"
        );
    }
    assert_eq!(entries(&scratch.0), ["stage"]);
    assert!(entries(&stage).is_empty());
}

// Oracle: a body or header cut short is an error, never a short file.
#[test]
fn unpack_rejects_truncated_records() {
    let scratch = Scratch::new();
    let mut cut = raw(&[("file", b"0123456789", false)]);
    cut.truncate(cut.len() - 3);
    let data = miniz_oxide::deflate::compress_to_vec_zlib(&cut, 6);
    let error = unpack(&data, &scratch.0, PAYLOAD_LIMIT).unwrap_err();
    assert!(error.to_string().contains("incomplete"), "{error}");
    assert!(!scratch.0.join("file").exists());

    let header = miniz_oxide::deflate::compress_to_vec_zlib(&[4, 0, 0], 6);
    assert!(unpack(&header, &scratch.0, PAYLOAD_LIMIT).is_err());

    // A body length near u32::MAX must not wrap the bounds check.
    let mut huge = raw(&[("f", b"", false)]);
    huge[2..6].copy_from_slice(&u32::MAX.to_le_bytes());
    let data = miniz_oxide::deflate::compress_to_vec_zlib(&huge, 6);
    assert!(unpack(&data, &scratch.0, PAYLOAD_LIMIT).is_err());
}

// Oracle: the size limit applies to the unpacked bytes. Known-bad: a
// payload one byte over the limit. Also corrupt and empty (the dev
// build's payload) input fail cleanly.
#[test]
fn unpack_rejects_oversize_and_corrupt_payloads() {
    let scratch = Scratch::new();
    let body = vec![0; 4096];
    let data = payload(&[("big", &body, false)]);
    let size = raw(&[("big", &body, false)]).len();
    assert!(unpack(&data, &scratch.0, size - 1).is_err());
    assert!(!scratch.0.join("big").exists());
    unpack(&data, &scratch.0, size).unwrap();
    for bad in [&b""[..], b"not zlib"] {
        let error = unpack(bad, &scratch.0, PAYLOAD_LIMIT).unwrap_err();
        assert!(error.to_string().contains("could not read"), "{error}");
    }
}

// Oracle: a fresh install has the app, the scanner and a marker naming
// the bundled version, and leaves no staging folder behind.
#[test]
fn install_fresh() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("installed");
    install(&app_payload(b"new"), &destination, "1.2.3").unwrap();
    assert_eq!(fs::read(destination.join(APP)).unwrap(), b"new");
    assert_eq!(
        fs::read_to_string(destination.join(MARKER)).unwrap(),
        "1.2.3"
    );
    assert_eq!(entries(&scratch.0), ["installed"]);
}

// Oracle: an older install is replaced; the same version is reinstalled
// (repair); a newer install is left byte for byte (downgrade guard).
#[test]
fn install_upgrades_but_never_downgrades() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("installed");
    install(&app_payload(b"old"), &destination, "1.0.0").unwrap();
    install(&app_payload(b"new"), &destination, "1.1.0").unwrap();
    assert_eq!(fs::read(destination.join(APP)).unwrap(), b"new");
    install(&app_payload(b"older"), &destination, "1.0.9").unwrap();
    assert_eq!(fs::read(destination.join(APP)).unwrap(), b"new");
    assert_eq!(
        fs::read_to_string(destination.join(MARKER)).unwrap(),
        "1.1.0"
    );
    assert_eq!(entries(&scratch.0), ["installed"]);
}

// Oracle: a folder without the marker is someone else's. Setup refuses,
// names the folder and says what to do, and leaves its files alone.
#[test]
fn install_refuses_a_foreign_folder() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("installed");
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("notes"), b"mine").unwrap();
    let error = install(&app_payload(b"new"), &destination, "1.0.0").unwrap_err();
    let text = error.to_string();
    assert!(
        text.contains(&destination.display().to_string()) && text.contains("Move or delete"),
        "{text}"
    );
    assert_eq!(fs::read(destination.join("notes")).unwrap(), b"mine");
    assert_eq!(entries(&destination), ["notes"]);
}

// Oracle: an install killed after moving the old copy aside (previous
// has the marker, destination is gone) is rolled back, then upgraded.
#[test]
fn install_recovers_an_interrupted_install() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("installed");
    install(&app_payload(b"old"), &destination, "1.0.0").unwrap();
    fs::rename(&destination, scratch.0.join(PREVIOUS)).unwrap();
    install(&app_payload(b"new"), &destination, "1.1.0").unwrap();
    assert_eq!(fs::read(destination.join(APP)).unwrap(), b"new");
    assert_eq!(entries(&scratch.0), ["installed"]);

    // Killed after the new copy landed: the leftover previous copy
    // (ours, it has the marker) goes away.
    let previous = scratch.0.join(PREVIOUS);
    fs::create_dir(&previous).unwrap();
    fs::write(previous.join(MARKER), "1.1.0").unwrap();
    install(&app_payload(b"newer"), &destination, "1.2.0").unwrap();
    assert_eq!(fs::read(destination.join(APP)).unwrap(), b"newer");
    assert_eq!(entries(&scratch.0), ["installed"]);
}

// Oracle: a `.pantry-setup-previous` without the marker is not ours and
// blocks the install with its path named.
#[test]
fn install_refuses_a_foreign_previous_folder() {
    let scratch = Scratch::new();
    let previous = scratch.0.join(PREVIOUS);
    fs::create_dir(&previous).unwrap();
    fs::write(previous.join("keep"), b"x").unwrap();
    let error = install(&app_payload(b"new"), &scratch.0.join("installed"), "1.0.0").unwrap_err();
    assert!(error.to_string().contains(PREVIOUS), "{error}");
    assert!(previous.join("keep").is_file());
}

// Oracle: only `.pantry-setup-<number>` folders of another pid go;
// look-alikes, files and our own stage stay.
#[test]
fn stale_stages_are_cleaned() {
    let scratch = Scratch::new();
    for name in [
        ".pantry-setup-4242",
        ".pantry-setup-7",
        ".pantry-setup-notes",
        "Pantry",
    ] {
        fs::create_dir(scratch.0.join(name)).unwrap();
        fs::write(scratch.0.join(name).join("f"), b"x").unwrap();
    }
    fs::write(scratch.0.join(".pantry-setup-99"), b"a file").unwrap();
    clean_stale_stages(&scratch.0, 7).unwrap();
    assert_eq!(
        entries(&scratch.0),
        [
            ".pantry-setup-7",
            ".pantry-setup-99",
            ".pantry-setup-notes",
            "Pantry"
        ]
    );

    // install() runs the cleanup first.
    fs::create_dir(scratch.0.join(".pantry-setup-4243")).unwrap();
    install(&app_payload(b"new"), &scratch.0.join("installed"), "1.0.0").unwrap();
    assert!(!scratch.0.join(".pantry-setup-4243").exists());
}

// Oracle: install failures with no app or scanner leave the old copy.
#[test]
fn install_keeps_the_old_copy_when_the_payload_is_incomplete() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("installed");
    install(&app_payload(b"old"), &destination, "1.0.0").unwrap();
    let partial = payload(&[(APP, b"new", true)]);
    assert!(install(&partial, &destination, "1.1.0").is_err());
    assert_eq!(fs::read(destination.join(APP)).unwrap(), b"old");
    assert_eq!(entries(&scratch.0), ["installed"]);
}

// Oracle: a recoverable previous copy (it has the marker) is never
// deleted while the destination is not a healthy install of ours. With a
// foreign destination Setup refuses, naming the destination, and the
// previous copy is byte for byte intact. With a damaged destination of
// ours, the previous copy is restored (seen through the downgrade guard
// keeping its newer app). Known-bad: the old code deleted the previous
// copy whenever the destination existed, then refused.
#[test]
fn install_never_deletes_a_recoverable_previous_copy() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("installed");
    let previous = scratch.0.join(PREVIOUS);
    install(&app_payload(b"only copy"), &previous, "9.0.0").unwrap();
    fs::create_dir(&destination).unwrap();
    fs::write(destination.join("theirs"), b"x").unwrap();
    let error = install(&app_payload(b"new"), &destination, "1.0.0").unwrap_err();
    assert!(
        error
            .to_string()
            .contains(&destination.display().to_string()),
        "{error}"
    );
    assert_eq!(fs::read(previous.join(APP)).unwrap(), b"only copy");
    assert_eq!(entries(&destination), ["theirs"]);

    // Ours but damaged (no app): the previous copy comes back.
    fs::remove_file(destination.join("theirs")).unwrap();
    fs::write(destination.join(MARKER), "0.1.0").unwrap();
    assert_eq!(
        install(&app_payload(b"new"), &destination, "1.0.0").unwrap(),
        Installed::KeptNewer
    );
    assert_eq!(fs::read(destination.join(APP)).unwrap(), b"only copy");
    assert_eq!(entries(&scratch.0), ["installed"]);
}

// Oracle: a same-version run of Setup is a repair: a deleted or
// corrupted scanner comes back byte for byte from the payload. Known-bad:
// a mutant that skips same-version installs (`installed >= bundled`)
// leaves the scanner missing or corrupt.
#[test]
fn same_version_reinstall_repairs_a_damaged_install() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("installed");
    install(&app_payload(b"app"), &destination, "1.0.0").unwrap();
    fs::remove_file(destination.join(SCANNER)).unwrap();
    assert_eq!(
        install(&app_payload(b"app"), &destination, "1.0.0").unwrap(),
        Installed::Bundled
    );
    assert_eq!(fs::read(destination.join(SCANNER)).unwrap(), b"scanner");
    fs::write(destination.join(SCANNER), b"garbage").unwrap();
    install(&app_payload(b"app"), &destination, "1.0.0").unwrap();
    assert_eq!(fs::read(destination.join(SCANNER)).unwrap(), b"scanner");
    assert_eq!(entries(&scratch.0), ["installed"]);
}

// Oracle: an older Setup over a newer install reports KeptNewer
// (run() then shows NEWER_INSTALLED and opens the installed app) and
// leaves the install byte for byte. Known-bad: the old code returned a
// bare Ok(()), the same as a real install, so run() said nothing.
#[test]
fn older_setup_over_newer_install_says_so() {
    let scratch = Scratch::new();
    let destination = scratch.0.join("installed");
    install(&app_payload(b"newer"), &destination, "2.0.0").unwrap();
    assert_eq!(
        install(&app_payload(b"older"), &destination, "1.0.0").unwrap(),
        Installed::KeptNewer
    );
    assert_eq!(fs::read(destination.join(APP)).unwrap(), b"newer");
    assert_eq!(NEWER_INSTALLED, "A newer Pantry is already installed.");
}

// Oracle: a payload file missing from the extracted download names
// that file in plain words and keeps the system text ("os error 2") as
// detail. Known-bad: the old code showed only the raw "No such file or
// directory (os error 2)".
#[test]
fn a_missing_payload_file_is_named() {
    let scratch = Scratch::new();
    let missing = scratch.0.join("Resources/pantry-setup.zlib");
    let text = explain(&read_payload(&missing).unwrap_err(), None);
    assert!(
        text.starts_with("Pantry Setup is missing a file from its download: ")
            && text.contains(&missing.display().to_string())
            && text.contains("Details: "),
        "{text}"
    );
    fs::create_dir_all(missing.parent().unwrap()).unwrap();
    fs::write(&missing, b"payload").unwrap();
    assert_eq!(read_payload(&missing).unwrap(), b"payload");
}
