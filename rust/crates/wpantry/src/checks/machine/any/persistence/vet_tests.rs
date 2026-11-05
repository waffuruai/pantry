use super::*;
use crate::checks::machine::testing::{roots, write};
use crate::utils::temp;

#[test]
fn signatures_and_quarantine() {
    assert_eq!(signature_of("/etc/hosts: code object is not signed at all\n"), Signature::Unsigned);
    assert_eq!(
        signature_of("Executable=/x\nCodeDirectory v=1 flags=0x20002(adhoc,linker-signed)\nSignature=adhoc\n"),
        Signature::AdHoc
    );
    assert_eq!(
        signature_of(
            "Identifier=com.apple.ls\nPlatform identifier=27\nAuthority=macOS Software Signing\nAuthority=Apple Root CA\n"
        ),
        Signature::Apple
    );
    assert_eq!(
        signature_of(
            "Authority=Developer ID Application: Example Inc (ABCDE12345)\nAuthority=Developer ID Certification Authority\n"
        ),
        Signature::Signed("Developer ID Application: Example Inc (ABCDE12345)".into())
    );
    assert_eq!(signature_of("Authority=Apple Mac OS Application Signing\n"), Signature::Signed("the App Store".into()));
    assert_eq!(signature_of(""), Signature::Unknown);

    let d = temp::TempDir::new("persist").unwrap();
    let prog = d.path().join("home/.hidden/agent");
    write(&prog, "x");
    let broken = |argv: &[&str]| match argv[..2] {
        ["codesign", "-dv"] => "Authority=Developer ID Application: X (T)\n".to_string(),
        ["codesign", "--verify"] => {
            format!("{}: invalid signature (code or signature have been modified)\n", argv[3])
        }
        ["xattr", "-p"] => "0081;6720a1b2;Safari;\n".into(),
        _ => String::new(),
    };
    let r = roots(d.path(), true, &broken);
    let v = vet(&r, &prog);
    assert_eq!(v.signature, Signature::Invalid("invalid signature (code or signature have been modified)".into()));
    assert_eq!(v.quarantined, Some(true));
    assert!(v.hidden);
    assert!(v.describe().contains("doesn't verify"), "{}", v.describe());
    let clean = |argv: &[&str]| match argv[..2] {
        ["codesign", "-dv"] => "Signature=adhoc\n".to_string(),
        ["xattr", "-p"] => format!("xattr: {}: No such xattr: com.apple.quarantine\n", argv[3]),
        _ => String::new(),
    };
    let r = roots(d.path(), true, &clean);
    let bin = d.path().join("home/bin/x");
    write(&bin, "x");
    assert_eq!(vet(&r, &bin), Vetted { signature: Signature::AdHoc, quarantined: Some(false), hidden: false });
    let linux = roots(d.path(), false, &clean);
    assert_eq!(vet(&linux, &bin).signature, Signature::Unknown, "codesign is macOS only");
}
