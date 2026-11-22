use super::*;

#[test]
fn parses_scanner_stamps() {
    assert_eq!(parse_utc("1970-01-01 00:00 UTC"), Some(0));
    assert_eq!(parse_utc("2026-11-21 16:30 UTC"), Some(1_795_278_600));
    assert_eq!(parse_utc("2026-11-21T16:30:05Z"), Some(1_795_278_605));
    for bad in [
        "",
        "yesterday",
        "2026-13-01 00:00 UTC",
        "2026-11-21 25:00 UTC",
    ] {
        assert_eq!(parse_utc(bad), None, "{bad}");
    }
}

#[test]
fn civil_round_trip() {
    for days in [-1, 0, 59, 60, 11_016, 20_778, 50_000] {
        let (y, m, d) = civil_from_days(days);
        assert_eq!(days_from_civil(y, m, d), days);
    }
}

fn fixture(transitions: Vec<(i64, i32)>, fixed_after: bool) -> Zone {
    Zone {
        transitions,
        initial: -21_600,
        fixed_after,
    }
}

#[test]
fn local_time_uses_the_offset_in_effect() {
    // Chicago-like: CDT from 2026-03-08 08:00 UTC, CST from 2026-11-01 07:00 UTC.
    let zone = fixture(
        vec![
            (1_772_956_800, -18_000),
            (1_793_516_400, -21_600),
            (2_000_000_000, -18_000),
        ],
        false,
    );
    assert_eq!(
        local_time_in("2026-11-21 16:30 UTC", Some(&zone)),
        "21 Nov 2026, 10:30"
    );
    assert_eq!(
        local_time_in("2026-07-04 16:30 UTC", Some(&zone)),
        "4 Jul 2026, 11:30"
    );
    // Unknown offset: the time stays UTC and is labelled.
    assert_eq!(
        local_time_in("2026-11-21 16:30 UTC", None),
        "21 Nov 2026, 16:30 UTC"
    );
    // Past the last transition of a slim file with DST rules: UTC.
    let slim = fixture(vec![(0, -21_600)], false);
    assert!(local_time_in("2026-11-21 16:30 UTC", Some(&slim)).ends_with("UTC"));
    // Unparseable text passes through untouched.
    assert_eq!(local_time_in("soon", Some(&zone)), "soon");
}

#[test]
fn reads_the_system_zone_file_when_present() {
    // Oracle: the parsed zone agrees with `date +%z` for now.
    #[cfg(unix)]
    if let (Ok(bytes), Ok(out)) = (
        std::fs::read("/etc/localtime"),
        std::process::Command::new("date").arg("+%z").output(),
    ) {
        let zone = parse_tzif(&bytes).expect("parse /etc/localtime");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let text = String::from_utf8_lossy(&out.stdout).trim().to_owned();
        let sign = if text.starts_with('-') { -1 } else { 1 };
        let hours: i32 = text[1..3].parse().unwrap();
        let minutes: i32 = text[3..5].parse().unwrap();
        if let Some(offset) = zone.offset_at(now) {
            assert_eq!(offset, sign * (hours * 3600 + minutes * 60));
        }
    }
    assert!(parse_tzif(b"not a zone file").is_none());
}
