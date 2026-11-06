//! The JSON report: the contract's envelope, schema 1
//! (`specs/cli-contract.md`), and with `--history` the logs under `history`.

use super::{Part, Report};
use crate::checks::Outcome;
use crate::utils::json::{J, obj};
use crate::{IMPL, SCHEMA, VERSION};

/// `scan --json`: the findings plus what was checked (schema 1).
pub fn envelope(scan: &Outcome) -> J {
    obj([
        ("schema", J::Int(SCHEMA)),
        ("impl", IMPL.into()),
        ("version", VERSION.into()),
        ("checked", J::Obj(scan.counts.iter().map(|(k, n)| (k.clone(), J::Int(*n))).collect())),
        ("unfixed", J::Int(scan.unfixed)),
        ("unknown_licenses", J::Int(scan.unknown_licenses)),
        ("findings", J::Arr(scan.findings.iter().map(|f| f.to_json()).collect())),
    ])
}

/// The report as JSON, by its part: the envelope (`findings`); the
/// envelope with the logs under `history` (`all`); the logs alone
/// (`history`, `exposure`, `remediation`, `audit`: `{schema, version,
/// since_days, exposures?, fixes?, scans?, events?}`); or the summary
/// (`{schema, version, summary}`).
pub fn report(report: &Report) -> J {
    let empty = super::History::default();
    let h = report.history.as_ref().unwrap_or(&empty);
    let list = |xs: Vec<serde_json::Value>| J::Arr(xs.iter().map(J::from).collect());
    let logs = |part: Part| {
        let mut pairs: Vec<(String, J)> = vec![("since_days".into(), J::Int(h.since_days))];
        if part.exposure() {
            pairs.push(("exposures".into(), list(h.exposures.iter().map(|e| e.to_json()).collect())));
        }
        if part.remediation() {
            pairs.push(("fixes".into(), list(h.fixes.iter().map(|f| f.to_json()).collect())));
        }
        if part.audit() {
            pairs.push(("scans".into(), list(h.scans.iter().map(|s| s.to_json()).collect())));
            pairs.push(("events".into(), list(h.events.iter().map(|e| e.to_json()).collect())));
        }
        J::Obj(pairs)
    };
    let head = || vec![("schema".to_string(), J::Int(SCHEMA)), ("version".to_string(), J::from(VERSION))];
    match report.part {
        Part::Findings => envelope(&report.outcome),
        Part::All => {
            let mut out = envelope(&report.outcome);
            if let J::Obj(pairs) = &mut out {
                pairs.push(("history".into(), logs(Part::All)));
            }
            out
        }
        Part::Summary => {
            let mut pairs = head();
            pairs.push(("summary".into(), super::summary::json(&super::summary::summary(report))));
            J::Obj(pairs)
        }
        part => {
            let mut pairs = head();
            if let J::Obj(rest) = logs(part) {
                pairs.extend(rest);
            }
            J::Obj(pairs)
        }
    }
}
