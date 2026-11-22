use super::{Backend, Every};
use std::{io, path::Path};

pub(super) fn read(path: &Path) -> io::Result<Option<String>> {
    match std::fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}

pub(super) fn description(every: Every, (hour, minute): (u32, u32)) -> String {
    if every == Every::Hour {
        return "Every hour".into();
    }
    let interval = match every {
        Every::Day => "Every day",
        Every::Week => "Mondays",
        Every::Month => "First day of each month",
        Every::Quarter => "January 1, April 1, July 1 and October 1",
        Every::Year => "January 1",
        Every::Hour => unreachable!(),
    };
    format!("{interval} at {hour:02}:{minute:02} local time")
}

fn parse_time(time: &str) -> Option<(u32, u32)> {
    let (hour, minute) = time.split_once(':')?;
    let (hour, minute) = (hour.parse().ok()?, minute.parse().ok()?);
    (hour < 24 && minute < 60).then_some((hour, minute))
}

pub(super) fn read_cadence(backend: Backend, text: &str) -> Option<(Every, (u32, u32))> {
    match backend {
        Backend::Launchd => launchd(text),
        Backend::Systemd => systemd(text),
        Backend::Cron => cron(text),
        Backend::Windows => {
            let (_, tail) = text.split_once("<Description>Pantry scan ")?;
            let (value, _) = tail.split_once("</Description>")?;
            let (every, at) = value.split_once(' ')?;
            Some((Every::parse(every)?, parse_time(at)?))
        }
    }
}

fn launchd(text: &str) -> Option<(Every, (u32, u32))> {
    let integer = |key| -> Option<u32> {
        let (_, value) = text.split_once(&format!("<key>{key}</key>"))?;
        value.trim_start().strip_prefix("<integer>")?.split_once("</integer>")?.0.parse().ok()
    };
    if integer("StartInterval") == Some(3600) {
        return Some((Every::Hour, (0, 0)));
    }
    let at = (integer("Hour")?, integer("Minute")?);
    let every = match (integer("Month"), integer("Day"), integer("Weekday")) {
        (None, None, None) => Every::Day,
        (None, None, Some(1)) => Every::Week,
        (None, Some(1), None) => Every::Month,
        (Some(1), Some(1), None) if text.matches("<key>Month</key>").count() == 4 => Every::Quarter,
        (Some(1), Some(1), None) => Every::Year,
        _ => return None,
    };
    Some((every, at))
}

fn systemd(text: &str) -> Option<(Every, (u32, u32))> {
    let when = text.lines().find_map(|line| line.strip_prefix("OnCalendar="))?;
    if when == "hourly" {
        return Some((Every::Hour, (0, 0)));
    }
    let (days, clock) = when.rsplit_once(' ')?;
    let every = match days {
        "*-*-*" => Every::Day,
        "Mon *-*-*" => Every::Week,
        "*-*-01" => Every::Month,
        "*-01,04,07,10-01" => Every::Quarter,
        "*-01-01" => Every::Year,
        _ => return None,
    };
    Some((every, parse_time(clock.strip_suffix(":00")?)?))
}

fn cron(text: &str) -> Option<(Every, (u32, u32))> {
    let mut fields = text.split_whitespace();
    let minute = fields.next()?.parse().ok()?;
    let hour = fields.next()?;
    let every = match (hour, fields.next()?, fields.next()?, fields.next()?) {
        ("*", "*", "*", "*") => Every::Hour,
        (_, "*", "*", "*") => Every::Day,
        (_, "*", "*", "1") => Every::Week,
        (_, "1", "*", "*") => Every::Month,
        (_, "1", "1,4,7,10", "*") => Every::Quarter,
        (_, "1", "1", "*") => Every::Year,
        _ => return None,
    };
    Some((every, (if hour == "*" { 0 } else { hour.parse().ok()? }, minute)))
}
