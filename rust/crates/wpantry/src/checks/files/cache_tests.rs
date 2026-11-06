use super::*;

#[test]
fn every_result_reads_back_as_it_was_kept() {
    let s = |id: &'static str| Suspect { file: "a.js".into(), id, line: 3, note: "n".into(), hard: true };
    let outs = [
        Out::Hidden(vec![Hidden { file: "x.md".into(), id: "HIDDEN-BIDI", note: "n".into(), line: 2, hard: true }]),
        Out::Suspects(FileResult {
            found: vec![s("SUSPECT-WALLET-SIGNING")],
            wallet: true,
            scripts: Some((vec![], vec![s("SUSPECT-THIRD-PARTY-SCRIPT")])),
            not_binary: None,
        }),
        Out::Suspects(FileResult { not_binary: Some("why".into()), ..Default::default() }),
        Out::Mptcp(None),
        Out::Mptcp(Some(Facts {
            opts_out: true,
            go: Some((1, 24, "go 1.24.0".into())),
            opt_in: Some(("SetMultipathTCP(true)", 4)),
            listen: None,
        })),
        Out::Documents(vec![Doc { file: "a.pdf".into(), id: "DOC-JS-ON-OPEN", note: "n".into(), hard: true }]),
        Out::Malware(Scanned { target: false, hits: Vec::new(), seen: None }),
        Out::Malware(Scanned { target: true, hits: Vec::new(), seen: None }),
        Out::Malware(Scanned {
            target: true,
            hits: vec![Hit {
                path: "/x/a.sh".into(),
                namespace: "ns".into(),
                rule: "R".into(),
                category: "miner".into(),
                description: "d".into(),
                sha256: "ab".into(),
            }],
            seen: Some(crate::checks::malware::observe::observe(b"pool = bad-c2.example:443")),
        }),
    ];
    let checks = [
        Check::Hidden,
        Check::Suspects(Kind::Repo),
        Check::Suspects(Kind::Installed),
        Check::Mptcp,
        Check::Mptcp,
        Check::Documents,
        Check::Malware(Scope::Programs),
        Check::Malware(Scope::All),
    ];
    for (check, out) in checks.iter().zip(&outs) {
        assert_eq!(from_json(*check, &to_json(out), std::path::Path::new("/x/a.sh")).as_ref(), Some(out), "{check:?}");
    }
    assert_eq!(from_json(Check::Malware(Scope::All), &json!("garbage"), std::path::Path::new("/x")), None);
    assert!(std::ptr::eq(intern("SUSPECT-X"), intern(&String::from("SUSPECT-X"))));
}

#[test]
fn a_record_reads_back_as_it_was_written() {
    let mut r = Record::default();
    r.versions.insert("hidden".into(), "v1".into());
    r.files.entry(String::new()).or_default().insert(
        "odd\tname\n.md".into(),
        Entry { print: 7, results: vec![("hidden".into(), 0, "[]".into()), ("mptcp".into(), 2, "null".into())] },
    );
    r.files.entry("a/b".into()).or_default().insert("c.rs".into(), Entry { print: u64::MAX, results: vec![] });
    assert_eq!(Record::parse(&r.text()), r);
    assert_eq!(Record::parse("not a record"), Record::default());
    assert_eq!(Record::parse(&format!("{MAGIC}\nnot json\t0\n")), Record::default(), "a broken line drops the record");
}

#[test]
fn versions_differ_by_check_and_hold_still() {
    assert_ne!(version(Check::Hidden, ""), version(Check::Documents, ""));
    assert_eq!(version(Check::Suspects(Kind::Repo), ""), version(Check::Suspects(Kind::Installed), ""));
    assert_eq!(version(Check::Mptcp, "a"), version(Check::Mptcp, "b"), "only the malware scan's rules salt it");
    assert_ne!(version(Check::Malware(Scope::All), "a"), version(Check::Malware(Scope::All), "b"));
}
