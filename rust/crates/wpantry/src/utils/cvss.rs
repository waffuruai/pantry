//! CVSS base scores from vector strings: 3.0 and 3.1 by the specification's
//! formula, 4.0 by its macro-vector lookup and interpolation, ported from
//! FIRST's reference calculator (github.com/FIRSTdotorg/cvss-v4-calculator,
//! BSD-2-Clause, Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and
//! contributors: the lookup table, the maximal vectors and the severity
//! distances are theirs). And the specification's words for a score.
//!
//! The CVSS 4.0 tables and scoring are used under this licence:
//!
//! > Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors
//! >
//! > Redistribution and use in source and binary forms, with or without
//! > modification, are permitted provided that the following conditions are
//! > met:
//! >
//! > 1. Redistributions of source code must retain the above copyright
//! >    notice, this list of conditions and the following disclaimer.
//! > 2. Redistributions in binary form must reproduce the above copyright
//! >    notice, this list of conditions and the following disclaimer in the
//! >    documentation and/or other materials provided with the distribution.
//! >
//! > THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
//! > IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
//! > TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
//! > PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//! > HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//! > SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
//! > TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
//! > PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
//! > LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//! > NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//! > SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

use std::collections::HashMap;

/// A base score and the CVSS version it was computed by ("3.1", "4.0").
#[derive(Clone, Debug, PartialEq)]
pub struct Score {
    pub value: f64,
    pub version: String,
}

/// The specification's word for a score: NONE (0.0), LOW, MEDIUM, HIGH,
/// CRITICAL. The same scale in 3.x and 4.0.
pub fn label(score: f64) -> &'static str {
    if score >= 9.0 {
        "CRITICAL"
    } else if score >= 7.0 {
        "HIGH"
    } else if score >= 4.0 {
        "MEDIUM"
    } else if score > 0.0 {
        "LOW"
    } else {
        "NONE"
    }
}

/// A severity word from any source, as CVSS says it: MODERATE (GitHub's)
/// and MEDIUM are MEDIUM, IMPORTANT (Red Hat's, Microsoft's) is HIGH,
/// NEGLIGIBLE (Ubuntu's) is LOW, MALICIOUS is CRITICAL; UNKNOWN and
/// anything else are "" (unrated).
pub fn word(label: &str) -> &'static str {
    match label.trim().to_ascii_uppercase().as_str() {
        "CRITICAL" | "MALICIOUS" => "CRITICAL",
        "HIGH" | "IMPORTANT" => "HIGH",
        "MEDIUM" | "MODERATE" => "MEDIUM",
        "LOW" | "NEGLIGIBLE" => "LOW",
        "NONE" => "NONE",
        _ => "",
    }
}

/// The best base score in an OSV record's `severity` list: the newest
/// version (4.0 over 3.1 over 3.0), the highest score within it.
pub fn of_record(rec: &serde_json::Value) -> Option<Score> {
    let mut best: Option<Score> = None;
    for s in crate::utils::json::arr_at(rec, "severity") {
        let Some(score) = s.get("score").and_then(serde_json::Value::as_str).and_then(self::score) else { continue };
        let better = match &best {
            None => true,
            Some(b) => (score.version.as_str(), score.value) > (b.version.as_str(), b.value),
        };
        if better {
            best = Some(score);
        }
    }
    best
}

/// The base score of a CVSS 3.x or 4.0 vector string, or None for anything
/// else (2.0 is not scored: no advisory wpantry reads carries one alone).
pub fn score(vector: &str) -> Option<Score> {
    let vector = vector.trim();
    let version = vector.strip_prefix("CVSS:")?.split('/').next()?;
    let value = match version {
        "3.0" | "3.1" => v3(vector)?,
        "4.0" => v4(vector)?,
        _ => return None,
    };
    Some(Score { value, version: version.to_string() })
}

fn metrics(vector: &str) -> HashMap<&str, &str> {
    vector.split('/').skip(1).filter_map(|p| p.split_once(':')).collect()
}

/// CVSS 3.x by the specification's formula.
fn v3(vector: &str) -> Option<f64> {
    let m = metrics(vector);
    let av = match *m.get("AV")? {
        "N" => 0.85,
        "A" => 0.62,
        "L" => 0.55,
        "P" => 0.2,
        _ => return None,
    };
    let ac = match *m.get("AC")? {
        "L" => 0.77,
        "H" => 0.44,
        _ => return None,
    };
    let scope_changed = m.get("S") == Some(&"C");
    let pr = match (*m.get("PR")?, scope_changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match *m.get("UI")? {
        "N" => 0.85,
        "R" => 0.62,
        _ => return None,
    };
    let cia = |k: &str| -> Option<f64> {
        match *m.get(k)? {
            "H" => Some(0.56),
            "L" => Some(0.22),
            "N" => Some(0.0),
            _ => None,
        }
    };
    let iss = 1.0 - (1.0 - cia("C")?) * (1.0 - cia("I")?) * (1.0 - cia("A")?);
    let impact = if scope_changed { 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15) } else { 6.42 * iss };
    let exploitability = 8.22 * av * ac * pr * ui;
    let roundup = |x: f64| (x * 10.0).ceil() / 10.0;
    Some(if impact <= 0.0 {
        0.0
    } else if scope_changed {
        roundup((1.08 * (impact + exploitability)).min(10.0))
    } else {
        roundup((impact + exploitability).min(10.0))
    })
}

/// The macro-vector scores of CVSS 4.0 (FIRST's `cvss_lookup.js`).
const LOOKUP: [(&str, f64); 270] = [
    ("000000", 10.0),
    ("000001", 9.9),
    ("000010", 9.8),
    ("000011", 9.5),
    ("000020", 9.5),
    ("000021", 9.2),
    ("000100", 10.0),
    ("000101", 9.6),
    ("000110", 9.3),
    ("000111", 8.7),
    ("000120", 9.1),
    ("000121", 8.1),
    ("000200", 9.3),
    ("000201", 9.0),
    ("000210", 8.9),
    ("000211", 8.0),
    ("000220", 8.1),
    ("000221", 6.8),
    ("001000", 9.8),
    ("001001", 9.5),
    ("001010", 9.5),
    ("001011", 9.2),
    ("001020", 9.0),
    ("001021", 8.4),
    ("001100", 9.3),
    ("001101", 9.2),
    ("001110", 8.9),
    ("001111", 8.1),
    ("001120", 8.1),
    ("001121", 6.5),
    ("001200", 8.8),
    ("001201", 8.0),
    ("001210", 7.8),
    ("001211", 7.0),
    ("001220", 6.9),
    ("001221", 4.8),
    ("002001", 9.2),
    ("002011", 8.2),
    ("002021", 7.2),
    ("002101", 7.9),
    ("002111", 6.9),
    ("002121", 5.0),
    ("002201", 6.9),
    ("002211", 5.5),
    ("002221", 2.7),
    ("010000", 9.9),
    ("010001", 9.7),
    ("010010", 9.5),
    ("010011", 9.2),
    ("010020", 9.2),
    ("010021", 8.5),
    ("010100", 9.5),
    ("010101", 9.1),
    ("010110", 9.0),
    ("010111", 8.3),
    ("010120", 8.4),
    ("010121", 7.1),
    ("010200", 9.2),
    ("010201", 8.1),
    ("010210", 8.2),
    ("010211", 7.1),
    ("010220", 7.2),
    ("010221", 5.3),
    ("011000", 9.5),
    ("011001", 9.3),
    ("011010", 9.2),
    ("011011", 8.5),
    ("011020", 8.5),
    ("011021", 7.3),
    ("011100", 9.2),
    ("011101", 8.2),
    ("011110", 8.0),
    ("011111", 7.2),
    ("011120", 7.0),
    ("011121", 5.9),
    ("011200", 8.4),
    ("011201", 7.0),
    ("011210", 7.1),
    ("011211", 5.2),
    ("011220", 5.0),
    ("011221", 3.0),
    ("012001", 8.6),
    ("012011", 7.5),
    ("012021", 5.2),
    ("012101", 7.1),
    ("012111", 5.2),
    ("012121", 2.9),
    ("012201", 6.3),
    ("012211", 2.9),
    ("012221", 1.7),
    ("100000", 9.8),
    ("100001", 9.5),
    ("100010", 9.4),
    ("100011", 8.7),
    ("100020", 9.1),
    ("100021", 8.1),
    ("100100", 9.4),
    ("100101", 8.9),
    ("100110", 8.6),
    ("100111", 7.4),
    ("100120", 7.7),
    ("100121", 6.4),
    ("100200", 8.7),
    ("100201", 7.5),
    ("100210", 7.4),
    ("100211", 6.3),
    ("100220", 6.3),
    ("100221", 4.9),
    ("101000", 9.4),
    ("101001", 8.9),
    ("101010", 8.8),
    ("101011", 7.7),
    ("101020", 7.6),
    ("101021", 6.7),
    ("101100", 8.6),
    ("101101", 7.6),
    ("101110", 7.4),
    ("101111", 5.8),
    ("101120", 5.9),
    ("101121", 5.0),
    ("101200", 7.2),
    ("101201", 5.7),
    ("101210", 5.7),
    ("101211", 5.2),
    ("101220", 5.2),
    ("101221", 2.5),
    ("102001", 8.3),
    ("102011", 7.0),
    ("102021", 5.4),
    ("102101", 6.5),
    ("102111", 5.8),
    ("102121", 2.6),
    ("102201", 5.3),
    ("102211", 2.1),
    ("102221", 1.3),
    ("110000", 9.5),
    ("110001", 9.0),
    ("110010", 8.8),
    ("110011", 7.6),
    ("110020", 7.6),
    ("110021", 7.0),
    ("110100", 9.0),
    ("110101", 7.7),
    ("110110", 7.5),
    ("110111", 6.2),
    ("110120", 6.1),
    ("110121", 5.3),
    ("110200", 7.7),
    ("110201", 6.6),
    ("110210", 6.8),
    ("110211", 5.9),
    ("110220", 5.2),
    ("110221", 3.0),
    ("111000", 8.9),
    ("111001", 7.8),
    ("111010", 7.6),
    ("111011", 6.7),
    ("111020", 6.2),
    ("111021", 5.8),
    ("111100", 7.4),
    ("111101", 5.9),
    ("111110", 5.7),
    ("111111", 5.7),
    ("111120", 4.7),
    ("111121", 2.3),
    ("111200", 6.1),
    ("111201", 5.2),
    ("111210", 5.7),
    ("111211", 2.9),
    ("111220", 2.4),
    ("111221", 1.6),
    ("112001", 7.1),
    ("112011", 5.9),
    ("112021", 3.0),
    ("112101", 5.8),
    ("112111", 2.6),
    ("112121", 1.5),
    ("112201", 2.3),
    ("112211", 1.3),
    ("112221", 0.6),
    ("200000", 9.3),
    ("200001", 8.7),
    ("200010", 8.6),
    ("200011", 7.2),
    ("200020", 7.5),
    ("200021", 5.8),
    ("200100", 8.6),
    ("200101", 7.4),
    ("200110", 7.4),
    ("200111", 6.1),
    ("200120", 5.6),
    ("200121", 3.4),
    ("200200", 7.0),
    ("200201", 5.4),
    ("200210", 5.2),
    ("200211", 4.0),
    ("200220", 4.0),
    ("200221", 2.2),
    ("201000", 8.5),
    ("201001", 7.5),
    ("201010", 7.4),
    ("201011", 5.5),
    ("201020", 6.2),
    ("201021", 5.1),
    ("201100", 7.2),
    ("201101", 5.7),
    ("201110", 5.5),
    ("201111", 4.1),
    ("201120", 4.6),
    ("201121", 1.9),
    ("201200", 5.3),
    ("201201", 3.6),
    ("201210", 3.4),
    ("201211", 1.9),
    ("201220", 1.9),
    ("201221", 0.8),
    ("202001", 6.4),
    ("202011", 5.1),
    ("202021", 2.0),
    ("202101", 4.7),
    ("202111", 2.1),
    ("202121", 1.1),
    ("202201", 2.4),
    ("202211", 0.9),
    ("202221", 0.4),
    ("210000", 8.8),
    ("210001", 7.5),
    ("210010", 7.3),
    ("210011", 5.3),
    ("210020", 6.0),
    ("210021", 5.0),
    ("210100", 7.3),
    ("210101", 5.5),
    ("210110", 5.9),
    ("210111", 4.0),
    ("210120", 4.1),
    ("210121", 2.0),
    ("210200", 5.4),
    ("210201", 4.3),
    ("210210", 4.5),
    ("210211", 2.2),
    ("210220", 2.0),
    ("210221", 1.1),
    ("211000", 7.5),
    ("211001", 5.5),
    ("211010", 5.8),
    ("211011", 4.5),
    ("211020", 4.0),
    ("211021", 2.1),
    ("211100", 6.1),
    ("211101", 5.1),
    ("211110", 4.8),
    ("211111", 1.8),
    ("211120", 2.0),
    ("211121", 0.9),
    ("211200", 4.6),
    ("211201", 1.8),
    ("211210", 1.7),
    ("211211", 0.7),
    ("211220", 0.8),
    ("211221", 0.2),
    ("212001", 5.3),
    ("212011", 2.4),
    ("212021", 1.4),
    ("212101", 2.4),
    ("212111", 1.2),
    ("212121", 0.5),
    ("212201", 1.0),
    ("212211", 0.3),
    ("212221", 0.1),
];

/// The maximal vectors of each equivalence class (FIRST's
/// `max_composed.js`): EQ1, EQ2, EQ3 by EQ6, EQ4, EQ5.
fn max_composed(eq: usize, level: u8, eq6: u8) -> &'static [&'static str] {
    match (eq, level, eq6) {
        (1, 0, _) => &["AV:N/PR:N/UI:N/"],
        (1, 1, _) => &["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
        (1, 2, _) => &["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"],
        (2, 0, _) => &["AC:L/AT:N/"],
        (2, 1, _) => &["AC:H/AT:N/", "AC:L/AT:P/"],
        (3, 0, 0) => &["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
        (3, 0, 1) => &["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"],
        (3, 1, 0) => &["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
        (3, 1, 1) => &[
            "VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/",
            "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/",
            "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/",
            "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/",
            "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/",
        ],
        (3, 2, 1) => &["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"],
        (4, 0, _) => &["SC:H/SI:S/SA:S/"],
        (4, 1, _) => &["SC:H/SI:H/SA:H/"],
        (4, 2, _) => &["SC:L/SI:L/SA:L/"],
        (5, 0, _) => &["E:A/"],
        (5, 1, _) => &["E:P/"],
        (5, 2, _) => &["E:U/"],
        _ => &[],
    }
}

/// The largest severity distance within each class, plus one (FIRST's
/// `max_severity.js`).
fn max_severity(eq: usize, level: u8, eq6: u8) -> Option<f64> {
    Some(match (eq, level, eq6) {
        (1, 0, _) => 1.0,
        (1, 1, _) => 4.0,
        (1, 2, _) => 5.0,
        (2, 0, _) => 1.0,
        (2, 1, _) => 2.0,
        (3, 0, 0) => 7.0,
        (3, 0, 1) => 6.0,
        (3, 1, 0) => 8.0,
        (3, 1, 1) => 8.0,
        (3, 2, 1) => 10.0,
        (4, 0, _) => 6.0,
        (4, 1, _) => 5.0,
        (4, 2, _) => 4.0,
        _ => return None,
    })
}

/// A metric's level within its class: how far from the most severe value.
fn level(metric: &str, value: &str) -> Option<f64> {
    Some(match (metric, value) {
        ("AV", "N") | ("PR", "N") | ("UI", "N") | ("AC", "L") | ("AT", "N") => 0.0,
        ("AV", "A") | ("PR", "L") | ("UI", "P") | ("AC", "H") | ("AT", "P") => 0.1,
        ("AV", "L") | ("PR", "H") | ("UI", "A") => 0.2,
        ("AV", "P") => 0.3,
        ("VC" | "VI" | "VA", "H") => 0.0,
        ("VC" | "VI" | "VA", "L") => 0.1,
        ("VC" | "VI" | "VA", "N") => 0.2,
        ("SC", "H") => 0.1,
        ("SC", "L") => 0.2,
        ("SC", "N") => 0.3,
        ("SI" | "SA", "S") => 0.0,
        ("SI" | "SA", "H") => 0.1,
        ("SI" | "SA", "L") => 0.2,
        ("SI" | "SA", "N") => 0.3,
        ("CR" | "IR" | "AR", "H") => 0.0,
        ("CR" | "IR" | "AR", "M") => 0.1,
        ("CR" | "IR" | "AR", "L") => 0.2,
        _ => return None,
    })
}

/// CVSS 4.0, as FIRST's `cvss_score.js` computes it.
fn v4(vector: &str) -> Option<f64> {
    let given = metrics(vector);
    for k in ["AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA"] {
        given.get(k)?;
    }
    // The value in effect: a modified metric over the base one; the threat
    // and requirement metrics default to their worst case.
    let m = |k: &str| -> &str {
        if let Some(v) = given.get(format!("M{k}").as_str()).filter(|v| **v != "X") {
            return v;
        }
        match (k, given.get(k).copied().unwrap_or("X")) {
            ("E", "X") => "A",
            ("CR" | "IR" | "AR", "X") => "H",
            (_, v) => v,
        }
    };
    if ["VC", "VI", "VA", "SC", "SI", "SA"].iter().all(|k| m(k) == "N") {
        return Some(0.0);
    }
    let eq1 = if m("AV") == "N" && m("PR") == "N" && m("UI") == "N" {
        0
    } else if (m("AV") == "N" || m("PR") == "N" || m("UI") == "N") && m("AV") != "P" {
        1
    } else {
        2
    };
    let eq2 = if m("AC") == "L" && m("AT") == "N" { 0 } else { 1 };
    let eq3 = if m("VC") == "H" && m("VI") == "H" {
        0
    } else if m("VC") == "H" || m("VI") == "H" || m("VA") == "H" {
        1
    } else {
        2
    };
    let eq4 = if m("MSI") == "S" || m("MSA") == "S" {
        0
    } else if m("SC") == "H" || m("SI") == "H" || m("SA") == "H" {
        1
    } else {
        2
    };
    let eq5 = match m("E") {
        "A" => 0,
        "P" => 1,
        "U" => 2,
        _ => return None,
    };
    let eq6 = if (m("CR") == "H" && m("VC") == "H")
        || (m("IR") == "H" && m("VI") == "H")
        || (m("AR") == "H" && m("VA") == "H")
    {
        0
    } else {
        1
    };
    let eqs: [u8; 6] = [eq1, eq2, eq3, eq4, eq5, eq6];
    let lookup = |e: [u8; 6]| -> Option<f64> {
        let key: String = e.iter().map(|d| char::from(b'0' + d)).collect();
        LOOKUP.iter().find(|(k, _)| *k == key).map(|(_, v)| *v)
    };
    let value = lookup(eqs)?;
    let lower = |i: usize| {
        let mut e = eqs;
        e[i] += 1;
        lookup(e)
    };
    let next_eq3eq6 = match (eq3, eq6) {
        (0, 0) => match (lower(5), lower(2)) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        },
        (1, 0) => lower(5),
        (0 | 1, 1) => lower(2),
        _ => {
            let mut e = eqs;
            e[2] += 1;
            e[5] += 1;
            lookup(e)
        }
    };
    let next = [lower(0), lower(1), next_eq3eq6, lower(3), lower(4)];
    // The maximal vectors of this macro-vector; the first the vector is no
    // more severe than gives the distances.
    let mut maxes: Vec<String> = vec![String::new()];
    for (eq, lvl) in [(1, eq1), (2, eq2), (3, eq3), (4, eq4), (5, eq5)] {
        let parts = max_composed(eq, lvl, eq6);
        maxes = maxes.iter().flat_map(|pre| parts.iter().map(move |p| format!("{pre}{p}"))).collect();
    }
    let names = ["AV", "PR", "UI", "AC", "AT", "VC", "VI", "VA", "SC", "SI", "SA", "CR", "IR", "AR"];
    let mut dist: HashMap<&str, f64> = HashMap::new();
    for max in &maxes {
        let mv: HashMap<&str, &str> = max.split('/').filter_map(|p| p.split_once(':')).collect();
        dist.clear();
        for k in names {
            let d = level(k, m(k))? - level(k, mv.get(k)?)?;
            dist.insert(k, d);
        }
        if dist.values().all(|d| *d >= 0.0) {
            break;
        }
    }
    let d = |ks: &[&str]| ks.iter().map(|k| dist[k]).sum::<f64>();
    let current = [
        d(&["AV", "PR", "UI"]),
        d(&["AC", "AT"]),
        d(&["VC", "VI", "VA", "CR", "IR", "AR"]),
        d(&["SC", "SI", "SA"]),
        0.0,
    ];
    let step = 0.1;
    let max_sev = [
        max_severity(1, eq1, 0),
        max_severity(2, eq2, 0),
        max_severity(3, eq3, eq6),
        max_severity(4, eq4, 0),
        Some(1.0),
    ];
    let (mut sum, mut n) = (0.0, 0);
    for i in 0..5 {
        let Some(lower_score) = next[i] else { continue };
        n += 1;
        let available = value - lower_score;
        let percent = if i == 4 { 0.0 } else { current[i] / (max_sev[i]? * step) };
        sum += available * percent;
    }
    let mean = if n == 0 { 0.0 } else { sum / n as f64 };
    let v = (value - mean).clamp(0.0, 10.0);
    // Half up, as decimal arithmetic rounds it: binary floating point
    // leaves an exact 5.65 a hair under, which would round down.
    Some((v * 10.0 + 0.5 + 1e-6).floor() / 10.0)
}

#[cfg(test)]
#[path = "cvss_tests.rs"]
mod tests;
