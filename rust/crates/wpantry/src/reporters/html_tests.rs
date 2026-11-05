use super::*;
use crate::finding::Finding;

#[test]
fn hostile_text_stays_json_data() {
    assert_eq!(TEMPLATE.matches(TOKEN).count(), 1);
    let hostile = "</script><img src=x onerror=alert(1)>&\"'\u{2028}";
    let html = render(&obj([("note", hostile.into())]));
    let payload = html
        .split("<script id=\"pantry-bundle\" type=\"application/json\">")
        .nth(1)
        .unwrap()
        .split("</script>")
        .next()
        .unwrap();
    assert!(!payload.contains(['<', '>', '&']));
    let parsed = crate::utils::json::parse(payload.as_bytes(), usize::MAX).unwrap();
    assert_eq!(parsed["note"], hostile);
    assert!(!html.contains(TOKEN));
}

#[test]
fn fonts_are_embedded_and_no_token_is_left() {
    let html = render(&obj([]));
    assert!(!html.contains("{{"), "a template token survived");
    assert_eq!(html.matches("data:font/woff2;base64,").count(), FONTS.len());
    assert!(!html.contains("http://") && !html.contains("https://fonts."), "nothing is fetched");
    assert_eq!(base64(b""), "");
    assert_eq!(base64(b"f"), "Zg==");
    assert_eq!(base64(b"fo"), "Zm8=");
    assert_eq!(base64(b"foo"), "Zm9v");
    assert_eq!(base64(b"foobar"), "Zm9vYmFy");
}

/// Every opened element is closed, in order, outside the script and
/// style elements (the viewer's own output is checked by
/// tests/html/test-viewer.cjs).
#[test]
fn template_is_well_formed() {
    let html = render(&obj([]));
    assert_eq!(well_formed(&strip(&strip(&html, "script"), "style")), None);
    assert_eq!(well_formed("<div><p>x</div>"), Some("mismatch: </div> closes p".into()));
    assert_eq!(well_formed("<div><br><img src=x>ok</div>"), None);
}

fn strip(html: &str, raw: &str) -> String {
    let (open, close) = (format!("<{raw}"), format!("</{raw}>"));
    let mut out = String::new();
    let mut rest = html;
    while let Some(start) = rest.find(&open) {
        let end = rest[start..].find(&close).map(|e| start + e + close.len()).expect("closed");
        out.push_str(&rest[..start]);
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

/// None when every element closes in order; the first problem otherwise.
fn well_formed(html: &str) -> Option<String> {
    const VOID: &[&str] =
        &["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"];
    let mut stack: Vec<String> = Vec::new();
    let mut rest = html;
    while let Some(lt) = rest.find('<') {
        let after = &rest[lt + 1..];
        if after.starts_with("!--") {
            let end = after.find("-->").map(|e| e + 3).unwrap_or(after.len());
            rest = &after[end..];
            continue;
        }
        let gt = after.find('>')?;
        let tag = &after[..gt];
        rest = &after[gt + 1..];
        if tag.starts_with('!') {
            continue;
        }
        let (closing, body) = match tag.strip_prefix('/') {
            Some(b) => (true, b),
            None => (false, tag),
        };
        let name: String =
            body.chars().take_while(|c| c.is_ascii_alphanumeric() || *c == '-').collect::<String>().to_lowercase();
        if name.is_empty() {
            return Some(format!("stray tag <{tag}>"));
        }
        if closing {
            match stack.pop() {
                Some(open) if open == name => {}
                Some(open) => return Some(format!("mismatch: </{name}> closes {open}")),
                None => return Some(format!("</{name}> closes nothing")),
            }
        } else if !VOID.contains(&name.as_str()) && !body.trim_end().ends_with('/') {
            stack.push(name);
        }
    }
    if rest.contains('>') {
        return Some("stray >".into());
    }
    if stack.is_empty() { None } else { Some(format!("unclosed {}", stack.join(", "))) }
}

fn fixture() -> Outcome {
    let f = |kind: &str, component: &str, id: &str, status: &str, fix_cmd: &str, auto: bool| Finding {
        kind: kind.into(),
        component: component.into(),
        version: "1.0".into(),
        location: format!("/w/{component}"),
        vuln_id: id.into(),
        status: status.into(),
        fix_cmd: fix_cmd.into(),
        fix_auto: auto,
        ..Default::default()
    };
    Outcome {
        scan_id: 7,
        findings: vec![
            f("brew", "openssl", "CVE-2026-1", "fail", "brew upgrade openssl", true),
            f("brew", "curl", "CVE-2026-2", "fail", "brew upgrade curl", true),
            f(
                "posture",
                "Firewall",
                "POSTURE-FIREWALL",
                "fail",
                "sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on",
                false,
            ),
            f("extension", "evil.ext", "MALICIOUS", "fail", "Remove the extension evil.ext", false),
            f("app", "Slack", "OUTDATED", "warn", "Update Slack from the vendor", false),
            f("unchecked", "CISA KEV", "UNCHECKED", "warn", "", false),
            f("project", "zip", "CVE-2026-3", "warn", "", false),
        ],
        counts: vec![("git repos".into(), 3), ("apps".into(), 40)],
        unfixed: 2,
        unknown_licenses: 0,
    }
}

/// The plan the viewer lists is wpantry's own: each non-auto fix as a
/// manual (fail) or optional (warn) step with the findings it covers,
/// the unattended ones as auto; gaps and fixless advisories take no step.
#[test]
fn bundle_carries_the_scan_its_plan_and_its_history() {
    let scan = fixture();
    let b = bundle(&scan, &Options::default(), "scan", J::Null, "mac", "eric");
    let text = b.dumps();
    let v = crate::utils::json::parse(text.as_bytes(), usize::MAX).unwrap();
    assert_eq!(v["runs"][0]["report"]["findings"].as_array().unwrap().len(), scan.findings.len());
    assert_eq!((v["host"].as_str(), v["user"].as_str(), v["scan_id"].as_i64()), (Some("mac"), Some("eric"), Some(7)));
    assert!(v["history"].is_null());
    let plan = v["plan"].as_array().unwrap();
    let step =
        |cmd: &str| plan.iter().find(|s| s["command"] == cmd).unwrap_or_else(|| panic!("no step for {cmd}: {text}"));
    for f in scan.findings.iter().filter(|f| !f.fix_cmd.is_empty()) {
        let s = step(&f.fix_cmd);
        let expected = if f.fix_auto {
            "auto"
        } else if f.status == "fail" {
            "manual"
        } else {
            "optional"
        };
        assert_eq!(s["mode"], expected, "{}", f.fix_cmd);
        let i = scan.findings.iter().position(|x| x == f).unwrap() as i64;
        assert!(s["findings"].as_array().unwrap().iter().any(|n| n.as_i64() == Some(i)), "{}", f.fix_cmd);
    }
    assert_eq!(plan.len(), 5, "one step per command, none for the gap or the fixless advisory: {text}");
    // Failures come first, as the terminal plan orders them.
    let modes: Vec<&str> = plan.iter().map(|s| s["mode"].as_str().unwrap()).collect();
    assert_eq!(modes, ["auto", "auto", "manual", "manual", "optional"]);
    // The rendered page is still well formed with a real bundle in it.
    let html = render(&b);
    assert_eq!(well_formed(&strip(&strip(&html, "script"), "style")), None);
}

#[test]
fn staging_preserves_previous_report_and_cleans_up() {
    let dir = std::env::temp_dir().join(format!("pantry-html-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let dest = dir.join("report.html");
    std::fs::write(&dest, "previous").unwrap();
    let output = Output::new(&dest).unwrap();
    let staged = output.staging.clone();
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "previous");
    drop(output);
    assert!(!staged.exists());
    Output::new(&dest).unwrap().write("next").unwrap();
    assert_eq!(std::fs::read_to_string(&dest).unwrap(), "next");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777, 0o600);
    }
    #[cfg(unix)]
    {
        let link = dir.join("link.html");
        std::os::unix::fs::symlink(&dest, &link).unwrap();
        Output::new(&link).unwrap().write("separate").unwrap();
        assert_eq!(std::fs::read_to_string(&dest).unwrap(), "next");
        assert_eq!(std::fs::read_to_string(&link).unwrap(), "separate");
        assert!(!std::fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
    }
    assert!(Output::new(&dir).is_err());
    assert!(Output::new(&dir.join("missing/report.html")).is_err());
    std::fs::remove_dir_all(dir).unwrap();
}
