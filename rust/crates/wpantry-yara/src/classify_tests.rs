use super::*;

fn c(name: &str) -> (Os, &'static str) {
    let (os, cat, _) = classify(name, &[], &[], &[], None);
    (os, cat)
}

#[test]
fn names_carry_os_and_category() {
    assert_eq!(c("SIGNATURE_BASE_MAL_XMR_Miner_May19_1"), (Os::Any, "miner"));
    assert_eq!(c("SEKOIA_Miner_Lin_Xmrig_Strings"), (Os::Linux, "miner"));
    assert_eq!(c("REVERSINGLABS_Win32_Virus_Elerad"), (Os::Windows, "virus"));
    assert_eq!(c("SIGNATURE_BASE_APT_MAL_LNX_Kobalos"), (Os::Linux, "malware"));
    assert_eq!(c("SIGNATURE_BASE_PUA_VULN_Driver_Openlibsysorg_Winringsys"), (Os::Any, "pua"));
    assert_eq!(c("SIGNATURE_BASE_HKTL_Mimikatz"), (Os::Any, "hacktool"));
    assert_eq!(c("SIGNATURE_BASE_OSX_Backdoor_Evilosx"), (Os::MacOS, "backdoor"));
    assert_eq!(c("SIGNATURE_BASE_WEBSHELL_PHP_OBFUSC_Fopo"), (Os::Any, "webshell"));
    assert_eq!(c("DITEKSHEN_MALWARE_Win_Coinminer02"), (Os::Windows, "miner"));
    assert_eq!(c("ESET_Kobalos"), (Os::Any, "malware"), "a bare family with the default score");
    assert_eq!(c("CobaltStrikeBeacon"), (Os::Any, "backdoor"), "camel case splits");
}

#[test]
fn meta_tags_imports_and_magic() {
    let meta = vec![("score".to_string(), Meta::Int(60))];
    assert_eq!(classify("GODMODERULES_IDDQD_God_Mode_Rule", &[], &meta, &[], None).1, "suspicious");
    let ours = vec![
        ("os".to_string(), Meta::Str(b"macos".to_vec())),
        ("category".to_string(), Meta::Str(b"clipper".to_vec())),
    ];
    assert_eq!(classify("Any_Thing", &[], &ours, &[], None), (Os::MacOS, "clipper", 75));
    let odd = vec![("os".to_string(), Meta::Str(b"plan9".to_vec()))];
    assert_eq!(classify("x", &[], &odd, &[], None).0, Os::Any);
    assert_eq!(classify("x", &["Ransomware".into()], &[], &[], None).1, "ransomware");
    assert_eq!(classify("x", &[], &[], &["pe".into()], None).0, Os::Windows);
    assert_eq!(classify("x", &[], &[], &[], Some(FileType::Elf)).0, Os::Linux);
    assert_eq!(classify("x", &[], &[], &[], Some(FileType::MachO)).0, Os::MacOS);
    assert_eq!(classify("x", &[], &[], &[], Some(FileType::Mz)).0, Os::Windows);
    assert!(is_malware("miner") && !is_malware("pua") && !is_malware("suspicious"));
    assert_eq!(Os::Linux.name(), "linux");
    assert_ne!(Os::host(), Os::Any);
}
