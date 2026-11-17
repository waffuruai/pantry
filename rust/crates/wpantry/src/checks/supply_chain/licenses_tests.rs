use super::*;
use crate::checks::Options;
use crate::checks::supply_chain::testing::CARGO_LOCK;
use crate::checks::supply_chain::{projects, testing};
use crate::error::Error;
use crate::sources::testing::ids;
use crate::utils::net::{Fake, Response};
use crate::utils::temp::TempDir;
use serde_json::json;

#[test]
fn spdx_expressions() {
    let allow = ids(&["MIT", "Apache-2.0", "BSD-3-Clause"]);
    assert_eq!(satisfied("MIT", &allow), Some(true));
    assert_eq!(satisfied("mit", &allow), Some(true));
    assert_eq!(satisfied("MIT OR GPL-3.0-only", &allow), Some(true));
    assert_eq!(satisfied("MIT AND GPL-3.0-only", &allow), Some(false));
    assert_eq!(satisfied("(Apache-2.0 OR MIT) AND BSD-3-Clause", &allow), Some(true));
    assert_eq!(satisfied("Apache-2.0 WITH LLVM-exception", &allow), Some(true));
    assert_eq!(satisfied("GPL-2.0+", &allow), Some(false));
    assert_eq!(satisfied("MIT AND", &allow), None);
    assert_eq!(judge(&[], &allow), Some(ids(&["UNKNOWN"])));
    assert_eq!(judge(&ids(&["GPL-3.0-only"]), &allow), Some(ids(&["GPL-3.0-only"])));
    assert_eq!(judge(&ids(&["GPL-3.0-only", "MIT"]), &allow), None);
    assert_eq!(judge(&ids(&["non-standard"]), &allow), Some(ids(&["non-standard"])), "custom terms need review");
}

/// `--licenses`: a license outside the allowlist warns, none at all is
/// only counted, and deps.dev unreachable is unchecked.
#[test]
fn licenses_outside_the_allowlist_warn() {
    let d = TempDir::new("licenses").unwrap();
    let net = Fake::new(|r| {
        if let Some(rest) = r.url.strip_prefix("https://api.deps.dev/v3/systems/cargo/packages/") {
            let licenses = match rest.split('/').next().unwrap_or("") {
                "serde" => json!(["GPL-3.0-only"]),
                "sedre" => json!(["MIT OR Apache-2.0"]),
                _ => json!([]),
            };
            return Ok(Response::ok(json!({"licenses": licenses}).to_string()));
        }
        testing::osv(r, &[]).unwrap_or_else(|| panic!("unexpected request to {}", r.url))
    });
    let mut s = testing::scan(&net, &d, Options { licenses: true, ..Default::default() });
    let (name, root) = testing::repo(&d, "app");
    testing::write(
        &root,
        "Cargo.lock",
        format!(
            "{CARGO_LOCK}\n[[package]]\nname = \"itoa\"\nversion = \"1.0.9\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n"
        ),
    );
    projects::projects(&mut s, &[(name, root.clone())]).unwrap();
    let lic = testing::by_id(&s, "LICENSE");
    assert_eq!(lic.len(), 1, "{:?}", s.findings);
    assert_eq!((lic[0].component.as_str(), lic[0].status.as_str()), ("serde", "warn"));
    assert_eq!(lic[0].note, format!("license GPL-3.0-only isn't in {LICENSES}"));
    assert_eq!(lic[0].location, root.join("Cargo.lock").to_string_lossy());
    assert_eq!(s.unknown_licenses, 1, "itoa has none; sedre's MIT passes");

    let d = TempDir::new("licenses-off").unwrap();
    let net = Fake::new(|r| {
        if r.url.starts_with("https://api.deps.dev/") {
            return Err(Error::Offline("deps.dev: down".into()));
        }
        testing::osv(r, &[]).unwrap_or_else(|| panic!("unexpected request to {}", r.url))
    });
    let mut s = testing::scan(&net, &d, Options { licenses: true, ..Default::default() });
    let (name, root) = testing::repo(&d, "app");
    testing::write(&root, "Cargo.lock", CARGO_LOCK);
    projects::projects(&mut s, &[(name, root)]).unwrap();
    assert_eq!(testing::unchecked(&s), ["dependency licenses (deps.dev)"]);
}
