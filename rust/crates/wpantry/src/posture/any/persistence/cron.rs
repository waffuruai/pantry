//! cron's tables and directories, and pending `at` jobs.

use super::{Inventory, Item, Roots, Source, entries, file_item, injects_in};
use crate::clipper::program_file;
use crate::system;
use std::collections::BTreeMap;

/// The command a crontab line runs: past the five time fields (or an
/// `@reboot`-style macro), and past the user field in a system crontab.
fn cron_command(line: &str, system_tab: bool) -> Option<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let first = *words.first()?;
    // An environment line (`MAILTO=x`, `LD_PRELOAD=…`) runs nothing.
    if first.contains('=') && !first.starts_with('@') {
        return None;
    }
    let skip = if first.starts_with('@') { 1 } else { 5 } + usize::from(system_tab);
    (words.len() > skip).then(|| words[skip..].join(" "))
}

fn cron_items(text: &str, location: &str, system_tab: bool, inv: &mut Inventory) {
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    for (i, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let injects = injects_in(line);
        let cmd = cron_command(line, system_tab);
        if cmd.is_none() && injects.is_empty() {
            continue;
        }
        let n = seen.entry(line.to_string()).or_default();
        *n += 1;
        let argv: Vec<String> =
            cmd.as_deref().unwrap_or("").split_whitespace().map(|w| w.trim_matches('"').to_string()).collect();
        inv.items.push(Item {
            source: Source::Cron,
            location: location.to_string(),
            ident: format!("{line}#{n}"),
            program: program_file(&argv),
            injects,
            line: i + 1,
        });
    }
}

pub(super) fn cron(r: &Roots, inv: &mut Inventory) {
    let user = (r.runner)(&["crontab", "-l"]);
    if !user.contains("no crontab for") {
        cron_items(&user, "crontab -l", false, inv);
    }
    let etc = r.sys("/etc/crontab");
    if let Ok(text) = system::read_capped(&etc, 1 << 20) {
        cron_items(&text, &r.show(&etc), true, inv);
    }
    if !r.macos {
        for path in entries(&r.sys("/etc/cron.d"), |_| true) {
            if let Ok(text) = system::read_capped(&path, 1 << 20) {
                cron_items(&text, &r.show(&path), true, inv);
            }
        }
        for dir in ["/etc/cron.hourly", "/etc/cron.daily", "/etc/cron.weekly", "/etc/cron.monthly"] {
            for path in entries(&r.sys(dir), |_| true) {
                inv.items.push(file_item(r, Source::Cron, &path));
            }
        }
    }
    inv.read.push(Source::Cron);
}

/// Pending `at` jobs: one-shot, but a way back all the same.
pub(super) fn at(r: &Roots, inv: &mut Inventory) {
    let out = (r.runner)(&["atq"]);
    for line in out.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let Some(job) = line.split_whitespace().next().filter(|j| j.chars().all(|c| c.is_ascii_digit())) else {
            continue;
        };
        inv.items.push(Item {
            source: Source::At,
            location: format!("at job {job}"),
            ident: line.to_string(),
            program: None,
            injects: Vec::new(),
            line: 0,
        });
    }
    inv.read.push(Source::At);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_past_the_time_and_user_fields() {
        // The crontab line's command past the user field.
        assert_eq!(cron_command("0 * * * * root /usr/bin/true", true).as_deref(), Some("/usr/bin/true"));
        assert_eq!(cron_command("@daily /bin/x", false).as_deref(), Some("/bin/x"));
        assert_eq!(cron_command("PATH=/bin", false), None);
        assert_eq!(cron_command("* * *", false), None);
    }
}
