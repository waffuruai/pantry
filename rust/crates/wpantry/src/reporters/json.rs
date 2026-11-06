//! The JSON report: the contract's envelope, schema 1
//! (`specs/cli-contract.md`), and with `--history` the logs under `history`.

use super::Report;
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

/// The envelope, and the logs as `history` when the report has them:
/// `{since_days, exposures, fixes, scans, events}`.
pub fn report(report: &Report) -> J {
    let mut out = envelope(&report.outcome);
    if let (J::Obj(pairs), Some(h)) = (&mut out, &report.history) {
        let list = |xs: Vec<serde_json::Value>| J::Arr(xs.iter().map(J::from).collect());
        pairs.push((
            "history".into(),
            obj([
                ("since_days", J::Int(h.since_days)),
                ("exposures", list(h.exposures.iter().map(|e| e.to_json()).collect())),
                ("fixes", list(h.fixes.iter().map(|f| f.to_json()).collect())),
                ("scans", list(h.scans.iter().map(|s| s.to_json()).collect())),
                ("events", list(h.events.iter().map(|e| e.to_json()).collect())),
            ]),
        ));
    }
    out
}
