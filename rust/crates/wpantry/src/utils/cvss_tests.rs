use super::*;

#[test]
fn cvss3_scores_by_the_formula() {
    let s = |v: &str| score(v).map(|s| (s.value, s.version));
    assert_eq!(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), Some((9.8, "3.1".into())));
    assert_eq!(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"), Some((6.1, "3.1".into())));
    assert_eq!(s("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"), Some((5.5, "3.0".into())));
    assert_eq!(s("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N"), Some((0.0, "3.1".into())));
    assert_eq!(s("AV:N/AC:L/Au:N/C:P/I:P/A:P"), None, "CVSS 2.0 is not scored");
    assert_eq!(s("CVSS:3.1/AV:X/AC:L"), None);
}

/// Vectors and the scores the specification's calculators give them,
/// across the macro-vectors, with threat and environmental metrics.
#[test]
fn cvss4_scores_as_the_reference_does() {
    for (v, want) in [
        ("CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:N/VI:L/VA:H/SC:H/SI:H/SA:H", 7.1),
        ("CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:L/VI:H/VA:N/SC:N/SI:H/SA:N", 6.7),
        ("CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:N/SC:L/SI:L/SA:L", 5.2),
        ("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:H/SC:L/SI:L/SA:H", 7.2),
        ("CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:L/VI:N/VA:H/SC:H/SI:L/SA:H", 9.1),
        ("CVSS:4.0/AV:N/AC:H/AT:N/PR:H/UI:N/VC:N/VI:N/VA:L/SC:L/SI:L/SA:H", 5.1),
        ("CVSS:4.0/AV:L/AC:H/AT:P/PR:L/UI:P/VC:L/VI:L/VA:L/SC:L/SI:H/SA:H", 2.3),
        ("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:A/VC:N/VI:N/VA:N/SC:L/SI:N/SA:H", 4.5),
        ("CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:N/VC:L/VI:N/VA:N/SC:H/SI:N/SA:N", 1.8),
        ("CVSS:4.0/AV:A/AC:H/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:N/SI:H/SA:L", 5.8),
        ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:L/SC:H/SI:L/SA:L", 7.0),
        ("CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:H/VI:N/VA:N/SC:N/SI:L/SA:L", 5.9),
        ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:A/VC:N/VI:N/VA:N/SC:H/SI:L/SA:H", 4.5),
        ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:N/SC:H/SI:H/SA:H", 8.4),
        ("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:N/VA:H/SC:H/SI:L/SA:H", 7.2),
        ("CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:P/VC:H/VI:N/VA:L/SC:H/SI:N/SA:N", 6.7),
        ("CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:H/VI:N/VA:N/SC:L/SI:H/SA:H", 7.0),
        ("CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:N/SC:H/SI:H/SA:L", 8.7),
        ("CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:H/VI:N/VA:N/SC:N/SI:L/SA:L", 5.1),
        ("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:N/VA:L/SC:N/SI:N/SA:L", 2.3),
        ("CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:A/VC:N/VI:H/VA:H/SC:H/SI:H/SA:H", 7.1),
        ("CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:P/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N", 5.9),
        ("CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:P/VC:H/VI:L/VA:H/SC:N/SI:H/SA:L", 6.9),
        ("CVSS:4.0/AV:P/AC:L/AT:N/PR:L/UI:A/VC:L/VI:H/VA:L/SC:L/SI:H/SA:L", 7.0),
        (
            "CVSS:4.0/AV:A/AC:H/AT:N/PR:H/UI:N/VC:H/VI:L/VA:L/SC:L/SI:H/SA:N/S:N/AU:N/R:I/V:D/RE:H/U:Amber/MAV:L/MAC:L/MAT:P/MPR:N/MUI:N/MVC:H/MVI:N/MVA:L/MSC:L/MSI:H/MSA:N/CR:H/IR:M/AR:L/E:U",
            3.5,
        ),
        (
            "CVSS:4.0/AV:A/AC:L/AT:N/PR:H/UI:A/VC:L/VI:N/VA:L/SC:N/SI:H/SA:N/S:N/AU:Y/R:A/V:D/RE:M/U:Clear/MAV:N/MAC:L/MAT:P/MPR:H/MUI:N/MVC:H/MVI:L/MVA:H/MSC:N/MSI:L/MSA:H/CR:M/IR:M/AR:H/E:A",
            7.0,
        ),
        (
            "CVSS:4.0/AV:N/AC:L/AT:P/PR:H/UI:P/VC:H/VI:N/VA:H/SC:N/SI:H/SA:N/S:N/AU:N/R:A/V:C/RE:H/U:Red/MAV:A/MAC:H/MAT:N/MPR:L/MUI:P/MVC:H/MVI:N/MVA:L/MSC:L/MSI:S/MSA:L/CR:H/IR:L/AR:L/E:A",
            6.8,
        ),
        (
            "CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:N/VI:H/VA:H/SC:L/SI:H/SA:H/S:P/AU:Y/R:A/V:C/RE:H/U:Amber/MAV:A/MAC:L/MAT:N/MPR:L/MUI:P/MVC:H/MVI:L/MVA:N/MSC:H/MSI:H/MSA:L/CR:L/IR:L/AR:H/E:U",
            1.7,
        ),
        (
            "CVSS:4.0/AV:P/AC:H/AT:N/PR:L/UI:N/VC:H/VI:H/VA:L/SC:L/SI:N/SA:N/S:P/AU:N/R:I/V:C/RE:L/U:Amber/MAV:L/MAC:H/MAT:N/MPR:N/MUI:A/MVC:H/MVI:N/MVA:L/MSC:H/MSI:L/MSA:H/CR:L/IR:L/AR:M/E:P",
            4.3,
        ),
        (
            "CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:P/VC:N/VI:H/VA:N/SC:L/SI:H/SA:L/S:P/AU:N/R:U/V:C/RE:L/U:Green/MAV:L/MAC:L/MAT:P/MPR:H/MUI:P/MVC:H/MVI:N/MVA:L/MSC:N/MSI:L/MSA:L/CR:H/IR:L/AR:H/E:U",
            0.5,
        ),
        (
            "CVSS:4.0/AV:L/AC:H/AT:N/PR:L/UI:P/VC:L/VI:N/VA:N/SC:L/SI:N/SA:N/S:N/AU:Y/R:I/V:D/RE:M/U:Red/MAV:N/MAC:H/MAT:N/MPR:H/MUI:N/MVC:H/MVI:H/MVA:N/MSC:L/MSI:N/MSA:H/CR:M/IR:M/AR:L/E:A",
            7.2,
        ),
        (
            "CVSS:4.0/AV:A/AC:L/AT:P/PR:N/UI:P/VC:L/VI:H/VA:H/SC:N/SI:H/SA:N/S:N/AU:Y/R:I/V:C/RE:M/U:Clear/MAV:P/MAC:L/MAT:N/MPR:L/MUI:P/MVC:H/MVI:L/MVA:H/MSC:N/MSI:L/MSA:S/CR:M/IR:H/AR:H/E:U",
            5.8,
        ),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
    ] {
        let got = score(v).unwrap_or_else(|| panic!("{v}"));
        assert_eq!((got.value, got.version.as_str()), (want, "4.0"), "{v}");
    }
    assert_eq!(score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H"), None, "a vector missing base metrics");
}

#[test]
fn the_words_are_the_specifications() {
    assert_eq!(
        [label(0.0), label(0.1), label(3.9), label(4.0), label(6.9), label(7.0), label(8.9), label(9.0), label(10.0)],
        ["NONE", "LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]
    );
}

/// Every vector in a file of `vector - score` lines (the format of the CVSS
/// libraries' test vectors) scores the same here: `CVSS4_VECTORS=file1:file2
/// cargo test --release -p wpantry --lib cvss4_vectors -- --ignored`.
#[test]
#[ignore]
fn cvss4_vectors_from_a_file() {
    let Some(files) = std::env::var_os("CVSS4_VECTORS") else { return };
    let (mut n, mut wrong) = (0, Vec::new());
    for f in std::env::split_paths(&files) {
        for line in std::fs::read_to_string(&f).unwrap().lines() {
            let Some((v, s)) = line.split_once(" - ") else { continue };
            let want: f64 = s.trim_matches(|c: char| c == '(' || c == ')' || c == ',').parse().unwrap();
            n += 1;
            let got = score(v).map(|s| s.value);
            if got != Some(want) {
                wrong.push(format!("{v}: {got:?}, want {want}"));
            }
        }
    }
    println!("{n} vectors, {} wrong", wrong.len());
    assert!(wrong.is_empty(), "{}", wrong.iter().take(20).cloned().collect::<Vec<_>>().join("\n"));
}
