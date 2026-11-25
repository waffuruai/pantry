use super::*;
use crate::finding::Finding;
use crate::utils::archive::compress::deflate;
use crate::utils::json::parse;

/// The bundle, its packed form and that deflated, which
/// `assets/report/test-viewer.cjs` decodes with the page's own code: what
/// the page reads is what this module writes.
const FIXTURE: &str = include_str!("../../assets/report/pack-fixture.json");

fn value(j: &J) -> Value {
    parse(j.dumps().as_bytes(), usize::MAX).unwrap()
}

fn fixture() -> (Value, J) {
    let v = parse(FIXTURE.as_bytes(), usize::MAX).unwrap();
    let bundle = J::from(&v["bundle"]);
    (v, bundle)
}

/// Strings that look like references or row markers, keys too, nested
/// rows, lists that are not rows, and the page's escaping hazards all come
/// back as they went in; so does a bundle large enough to be deflated.
#[test]
fn read_gives_back_what_write_took() {
    let (_, bundle) = fixture();
    assert_eq!(read(&write(&bundle)), Some(value(&bundle)));
    let big = J::Arr((0..120_000).map(|i| J::Obj(vec![("id".into(), J::Str(format!("F-{i}")))])).collect());
    let text = write(&big);
    assert!(text.starts_with(r#"{"pantry_deflated": ""#), "over {DEFLATE_OVER} bytes packed: {}", &text[..40]);
    assert_eq!(read(&text), Some(value(&big)));
    let plain = obj([("runs", J::Arr(vec![]))]);
    assert_eq!(unpack(&value(&plain)), Some(value(&plain)), "an unpacked bundle passes through");
}

#[test]
fn read_refuses_what_write_never_writes() {
    for bad in [
        "not json",
        r#"{"pantry_packed": 1, "strings": ["abcd"], "data": "~1"}"#,
        r#"{"pantry_packed": 1, "strings": ["abcd"], "data": "~?"}"#,
        r#"{"pantry_packed": 1, "strings": [], "data": ["~", ["a"], [1, 2]]}"#,
        r#"{"pantry_packed": 1, "strings": [], "data": ["~", "a"]}"#,
        r#"{"pantry_packed": 1, "strings": [1], "data": 1}"#,
        r#"{"pantry_deflated": "*"}"#,
        r#"{"pantry_deflated": "AAAA"}"#,
    ] {
        assert_eq!(read(bad), None, "{bad}");
    }
}

/// The shared fixture is this module's output, byte for byte, so the
/// viewer test decodes exactly what a report carries. After a change to
/// the format, regenerate `packed` and `deflated` from the values printed.
#[test]
fn the_viewer_fixture_is_what_write_writes() {
    let (v, bundle) = fixture();
    let packed = pack(&bundle).dumps();
    let deflated = crate::utils::base64::encode(&deflate(packed.as_bytes()));
    assert_eq!(v["packed"], parse(packed.as_bytes(), usize::MAX).unwrap(), "packed: {packed}");
    assert_eq!(v["deflated"], Value::from(deflated.clone()), "deflated: {deflated}");
}

/// A finding as a lockfile copy repeats it: one advisory, its own path.
fn copy(i: usize) -> J {
    Finding {
        kind: "project".into(),
        component: "vite".into(),
        version: "6.4.4".into(),
        location: format!("/Users/me/Library/CloudStorage/Drive/old/copy-{i}/package-lock.json"),
        vuln_id: "GHSA-8g5g-mxqh-grgj".into(),
        status: "fail".into(),
        fixed: "6.4.5".into(),
        severity: "HIGH".into(),
        note: "Vite's dev server can be made to read files outside its root through a crafted URL".into(),
        fix_cmd: "npm install vite@6.4.5".into(),
        dep_scope: "runtime".into(),
        affected_range: ">=6.0.0, <6.4.5".into(),
        ..Default::default()
    }
    .to_json()
}

/// N copies of one advisory cost far less than N findings: each repeat
/// past the first is under half of one finding's JSON (its own path and
/// id are most of it). Fails with the strings left inline (rows alone) or
/// with no packing at all.
#[test]
fn repeated_advisories_pack_small() {
    let n = 500;
    let size = |n: usize| pack(&J::Arr((0..n).map(copy).collect())).dumps().len();
    let one = copy(0).dumps().len();
    let per_repeat = (size(n) - size(1)) / (n - 1);
    assert!(per_repeat * 2 < one, "{per_repeat} bytes per repeat, one finding is {one}");
}

/// A machine scan's worth of copies, as the page carries it: a twentieth
/// of its plain JSON. Fails without the deflate step (packing alone is
/// about a third).
#[test]
fn a_large_scan_is_deflated_small() {
    let findings = J::Arr((0..20_000).map(copy).collect());
    let (plain, page) = (findings.dumps().len(), write(&findings).len());
    assert!(page * 20 < plain, "{page} bytes on the page for {plain} of JSON");
}
