//! The JSON report (`scan --json`): the contract's envelope, schema 1
//! (`specs/cli-contract.md`).

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
