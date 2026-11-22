use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    println!("cargo:rerun-if-env-changed=PANTRY_SETUP_PAYLOAD");
    let build_dir = PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"));
    let setup = build_dir.join("pantry-setup.zlib");
    if let Some(payload) = env::var_os("PANTRY_SETUP_PAYLOAD") {
        let payload = PathBuf::from(payload);
        println!("cargo:rerun-if-changed={}", payload.display());
        fs::copy(payload, setup).expect("copy Pantry Setup payload");
    } else {
        fs::write(setup, []).expect("write empty development payload");
    }

    if env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    // Embed the waffle in the Windows executable for Explorer and shortcuts.
    let resources = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"))
        .join("assets/Pantry.res");
    println!("cargo:rerun-if-changed={}", resources.display());

    let input = if env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu") {
        println!("cargo:rerun-if-env-changed=WINDRES");
        let default = if cfg!(windows) {
            "windres"
        } else {
            "x86_64-w64-mingw32-windres"
        };
        let compiler = env::var_os("WINDRES").unwrap_or_else(|| default.into());
        let object = PathBuf::from(env::var_os("OUT_DIR").expect("build output directory"))
            .join("pantry-icon.o");
        let status = Command::new(compiler)
            .args(["-J", "res", "-O", "coff"])
            .arg(&resources)
            .arg(&object)
            .status()
            .expect("run windres to embed the Pantry icon");
        assert!(status.success(), "windres could not embed the Pantry icon");
        object
    } else {
        resources
    };
    println!(
        "cargo:rustc-link-arg-bin=wpantry-desktop={}",
        input.display()
    );
    println!("cargo:rustc-link-arg-bin=wpantry-setup={}", input.display());
}
