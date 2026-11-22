//! Scanner timestamps (UTC) shown in local time, read from the system's
//! zone file without a time zone dependency.

use std::path::PathBuf;
use std::sync::OnceLock;

/// Days since 1970-01-01 for a proleptic Gregorian date (Howard Hinnant's
/// `days_from_civil`), the inverse of the scanner's `civil_from_days`.
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (
        if m <= 2 {
            yoe + era * 400 + 1
        } else {
            yoe + era * 400
        },
        m,
        d,
    )
}

/// Seconds since the epoch for the scanner's `2026-11-21 16:30 UTC` stamps
/// (also accepts `T` and `Z`, and seconds).
pub fn parse_utc(text: &str) -> Option<i64> {
    let text = text.trim();
    let text = text
        .strip_suffix(" UTC")
        .or_else(|| text.strip_suffix('Z'))
        .unwrap_or(text);
    let (date, time) = text.split_once([' ', 'T'])?;
    let mut date = date.split('-').map(str::parse::<i64>);
    let (y, m, d) = (date.next()?.ok()?, date.next()?.ok()?, date.next()?.ok()?);
    let mut time = time.split(':').map(str::parse::<i64>);
    let (h, min) = (time.next()?.ok()?, time.next()?.ok()?);
    let s = time.next().transpose().ok()?.unwrap_or(0);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 || min > 59 || s > 60 {
        return None;
    }
    Some(days_from_civil(y, m, d) * 86_400 + h * 3600 + min * 60 + s)
}

/// The local time zone's UTC offsets, read once from the system's TZif
/// file. `None` on Windows and wherever the file can't be read.
// TODO: read the Windows offset (GetTimeZoneInformation needs a dependency
// or unsafe code, both avoided here); Windows shows UTC, labelled.
struct Zone {
    /// (transition time, offset in seconds after it), sorted.
    transitions: Vec<(i64, i32)>,
    /// The offset before the first transition.
    initial: i32,
    /// True when the file's footer rule has no daylight saving, so the
    /// last offset holds after the last transition.
    fixed_after: bool,
}

impl Zone {
    fn offset_at(&self, t: i64) -> Option<i32> {
        match self.transitions.partition_point(|(at, _)| *at <= t) {
            0 => Some(self.initial),
            n if n == self.transitions.len() && !self.fixed_after => None,
            n => Some(self.transitions[n - 1].1),
        }
    }
}

/// Parse a TZif (RFC 8536) file, version 2 or later, using the 64-bit
/// section. A slim file whose DST rule lives only in the footer gives
/// `None` past its last transition, and callers then fall back to UTC.
fn parse_tzif(bytes: &[u8]) -> Option<Zone> {
    let be32 = |at: usize| -> Option<u32> {
        Some(u32::from_be_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
    };
    let counts = |base: usize| -> Option<[usize; 6]> {
        if bytes.get(base..base + 4)? != b"TZif" {
            return None;
        }
        let mut out = [0; 6];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = be32(base + 20 + 4 * i)? as usize;
        }
        Some(out)
    };
    let [isut, isstd, leap, time, types, chars] = counts(0)?;
    if *bytes.get(4)? < b'2' {
        return None;
    }
    let v1 = time * 5 + types * 6 + chars + leap * 8 + isstd + isut;
    let base = 44 + v1;
    let [isut, isstd, leap, time, types, chars] = counts(base)?;
    let mut at = base + 44;
    let mut times = Vec::with_capacity(time);
    for i in 0..time {
        let raw = bytes.get(at + 8 * i..at + 8 * i + 8)?;
        times.push(i64::from_be_bytes(raw.try_into().ok()?));
    }
    at += time * 8;
    let indices = bytes.get(at..at + time)?.to_vec();
    at += time;
    let mut offsets = Vec::with_capacity(types);
    let mut initial = None;
    for i in 0..types {
        let entry = bytes.get(at + 6 * i..at + 6 * i + 6)?;
        let offset = i32::from_be_bytes(entry[..4].try_into().ok()?);
        if entry[4] == 0 && initial.is_none() {
            initial = Some(offset);
        }
        offsets.push(offset);
    }
    at += types * 6 + chars + leap * 12 + isstd + isut;
    let footer = bytes.get(at..).unwrap_or_default();
    let footer = std::str::from_utf8(footer).unwrap_or_default().trim();
    let transitions = times
        .into_iter()
        .zip(indices)
        .map(|(t, index)| Some((t, *offsets.get(index as usize)?)))
        .collect::<Option<Vec<_>>>()?;
    Some(Zone {
        initial: initial.or_else(|| offsets.first().copied())?,
        fixed_after: !footer.contains(','),
        transitions,
    })
}

fn zone() -> Option<&'static Zone> {
    static ZONE: OnceLock<Option<Zone>> = OnceLock::new();
    ZONE.get_or_init(|| {
        if cfg!(windows) {
            return None;
        }
        let tz = std::env::var("TZ").ok();
        let tz = tz.as_deref().map(|tz| tz.strip_prefix(':').unwrap_or(tz));
        let candidates: Vec<PathBuf> = match tz {
            Some(name) if name.starts_with('/') => vec![PathBuf::from(name)],
            Some(name) if !name.is_empty() && !name.contains("..") => [
                "/usr/share/zoneinfo",
                "/var/db/timezone/zoneinfo",
                "/usr/lib/zoneinfo",
            ]
            .iter()
            .map(|dir| PathBuf::from(dir).join(name))
            .collect(),
            _ => vec![PathBuf::from("/etc/localtime")],
        };
        candidates
            .iter()
            .find_map(|path| std::fs::read(path).ok())
            .and_then(|bytes| parse_tzif(&bytes))
    })
    .as_ref()
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

fn format_time(t: i64, suffix: &str) -> String {
    let (y, m, d) = civil_from_days(t.div_euclid(86_400));
    let rem = t.rem_euclid(86_400);
    format!(
        "{d} {} {y}, {:02}:{:02}{suffix}",
        MONTHS[(m - 1) as usize],
        rem / 3600,
        (rem % 3600) / 60
    )
}

/// A scanner stamp in the computer's local time, such as
/// `21 Nov 2026, 10:30`. Where the offset is unknown (Windows, or a zone
/// file Pantry can't read) the time stays in UTC and says so.
pub fn local_time(stamp: &str) -> String {
    local_time_in(stamp, zone())
}

fn local_time_in(stamp: &str, zone: Option<&Zone>) -> String {
    let Some(t) = parse_utc(stamp) else {
        return stamp.to_owned();
    };
    match zone.and_then(|zone| zone.offset_at(t)) {
        Some(offset) => format_time(t + i64::from(offset), ""),
        None => format_time(t, " UTC"),
    }
}

#[cfg(test)]
#[path = "time_tests.rs"]
mod tests;
