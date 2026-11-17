//! Calendar dates as days since 1970-01-01, without a crate.

/// Days since 1970-01-01 for an ISO date (YYYY-MM-DD).
pub fn parse_date(s: &str) -> Option<i64> {
    let mut it = s.splitn(3, '-');
    let (y, m, d) = (it.next()?, it.next()?, it.next()?);
    if y.len() != 4 || m.len() != 2 || d.len() != 2 {
        return None;
    }
    let (y, m, d): (i64, i64, i64) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    Some(days_from_civil(y, m, d))
}

/// Howard Hinnant's days_from_civil.
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

/// Today (UTC), in days since 1970-01-01.
pub fn today() -> i64 {
    (crate::utils::os::now() / 86400.0).floor() as i64
}

/// Day precision is enough: the grace period is counted in days.
pub fn epoch(stamp: &str) -> f64 {
    stamp.get(..10).and_then(parse_date).map(|d| d as f64 * 86400.0).unwrap_or(0.0)
}
