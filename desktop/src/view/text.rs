//! The words the window shows, kept apart from drawing so tests can read
//! them: names, paths, plain sentences, scopes and what a fix command does.

use crate::data::Finding;

/// This account's home folder, for showing paths as `~/...`.
pub(super) fn home_dir() -> Option<String> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var(var).ok().filter(|home| home.len() > 1)
}

/// A path as people should read it: the home folder as `~`, and when it is
/// still longer than `max` characters, the middle replaced by `…` so the
/// start and the folder name at the end both stay visible.
///
/// ```ignore
/// display_path("/Users/sam/Projects/site", Some("/Users/sam"), 56) == "~/Projects/site"
/// display_path("/var/folders/y2/abcdefghijklmnop/T/build-1234/project", None, 30)
///     == "/var/folders/…uild-1234/project"
/// ```
pub fn display_path(path: &str, home: Option<&str>, max: usize) -> String {
    let short = home
        .and_then(|home| {
            let rest = path.strip_prefix(home.trim_end_matches(['/', '\\']))?;
            (rest.is_empty() || rest.starts_with(['/', '\\'])).then(|| format!("~{rest}"))
        })
        .unwrap_or_else(|| path.to_owned());
    let chars: Vec<char> = short.chars().collect();
    if chars.len() <= max || max < 8 {
        return short;
    }
    // Keep more of the end: it names the project or file.
    let head = (max - 1) * 2 / 5;
    let tail = max - 1 - head;
    let mut out: String = chars[..head].iter().collect();
    out.push('…');
    out.extend(&chars[chars.len() - tail..]);
    out
}

/// The longest component name a sentence quotes, in characters.
pub(super) const NAME_MAX: usize = 40;

/// Scanner text for one line: hidden characters gone, every run of
/// whitespace (newlines included) one space, and at most `max` characters,
/// cut at a word with "…" when longer.
///
/// ```ignore
/// one_line("a\n\n b", 80) == "a b"
/// one_line("one two three", 8) == "one two…"
/// ```
pub fn one_line(text: &str, max: usize) -> String {
    let clean = crate::pantry::clean(text);
    let joined = clean.split_whitespace().collect::<Vec<_>>().join(" ");
    if joined.chars().count() <= max {
        return joined;
    }
    let cut: String = joined.chars().take(max.saturating_sub(1)).collect();
    let cut = match cut.rfind(' ') {
        Some(at) if at > cut.len() / 2 => &cut[..at],
        _ => cut.as_str(),
    };
    format!("{}…", cut.trim_end_matches([' ', ',', ';', ':', '.']))
}

/// A finding's name as sentences quote it: on one line and short, so a
/// long or multi-line name never pushes the rest out of view.
pub fn display_name(finding: &Finding) -> String {
    let name = one_line(&finding.component, NAME_MAX);
    if name.is_empty() {
        "This item".to_owned()
    } else {
        name
    }
}

/// One plain sentence for a finding: what it is and why it matters.
///
/// The "security flaw" and "no fix yet" words belong to published
/// advisories only ([`crate::explain::is_advisory`]); Pantry's own checks
/// lead with what the check found ([`crate::explain::own_lead`]).
pub fn plain_sentence(finding: &Finding) -> String {
    let name = display_name(finding);
    let name = name.as_str();
    let first_sentence = || {
        let note = one_line(&finding.note, 400);
        let end = note.find(". ").map_or(note.len(), |i| i + 1);
        let text = one_line(&note[..end], 160);
        if text.is_empty() {
            format!("{name} needs a look.")
        } else {
            text
        }
    };
    if let Some(lead) = (finding.kind != "unchecked")
        .then(|| crate::explain::own_lead(finding, name))
        .flatten()
    {
        return lead;
    }
    match finding.kind.as_str() {
        "unchecked" => format!("{name} could not be checked this time."),
        "secret" => format!(
            "A password or key is saved in a file in {name}. Anyone who can read the project can use it."
        ),
        "malware" | "suspect-code" => format!("{name} looks like known harmful software."),
        "posture" | "config" | "persistence" | "license" | "hidden-text" | "install-script"
        | "repo-hook" | "document" | "queue" => first_sentence(),
        _ if !crate::explain::is_advisory(finding) => first_sentence(),
        // What the flaw lets someone do, when the advisory says.
        _ => match crate::explain::short_consequence(finding) {
            Some(consequence) => format!("{} {consequence}", advisory_lead(finding, name)),
            None => advisory_lead(finding, name),
        },
    }
}

/// The lead every published-advisory row starts with, on the home page and
/// under "From earlier scans" alike:
///
/// ```text
/// left-pad has a security flaw with no fix yet.
/// left-pad is out of date and has a security flaw that attackers are using.
/// ```
fn advisory_lead(finding: &Finding, name: &str) -> String {
    let exploited = if finding.kev {
        " that attackers are using"
    } else {
        ""
    };
    if finding.fixed.is_empty() {
        let comma = if finding.kev { "," } else { "" };
        format!("{name} has a security flaw{exploited}{comma} with no fix yet.")
    } else {
        format!("{name} is out of date and has a security flaw{exploited}.")
    }
}

/// Needs attention now: exploited, critical, high, or a failing check.
pub(super) fn urgent(finding: &Finding) -> bool {
    finding.kind != "unchecked"
        && (finding.kev
            || matches!(
                finding.severity.to_ascii_lowercase().as_str(),
                "critical" | "high"
            )
            || (finding.status == "fail" && finding.severity.is_empty()))
}

/// True when a finding matches the search text (already lower-cased): its
/// name, place, ids (its own, its aliases, its weakness types), kind,
/// severity, the scanner's note, the advisory's summary, and the plain
/// sentences the window shows for it.
pub fn matches_search(f: &Finding, search: &str) -> bool {
    if search.is_empty() {
        return true;
    }
    let shown = [plain_sentence(f), crate::explain::explain(f).sentence];
    [
        &f.component,
        &f.location,
        &f.vuln_id,
        &f.kind,
        &f.severity,
        &f.note,
        &f.summary,
    ]
    .into_iter()
    .chain(&f.aliases)
    .chain(&f.cwe)
    .chain(&shown)
    .any(|s| s.to_lowercase().contains(search))
}

/// Where a scan looked, for people: the fixed scopes in words, folders
/// with the home folder as `~` and long paths shortened in the middle.
///
/// ```ignore
/// scope_place("repos:/Users/sam/site,/Users/sam/app") == "~/site, ~/app"
/// ```
pub(super) fn scope_place(raw: &str) -> String {
    let named = scope(raw, false);
    if named != "Selected folders" && named != "This computer" {
        return named;
    }
    let base = raw.split([';', '+']).next().unwrap_or("");
    let Some((_, paths)) = base.split_once(':') else {
        return named;
    };
    let home = home_dir();
    let shown: Vec<String> = paths
        .split(',')
        .filter(|path| !path.is_empty())
        .map(|path| display_path(&one_line(path, 400), home.as_deref(), 48))
        .collect();
    if shown.is_empty() {
        named
    } else {
        shown.join(", ")
    }
}

pub(super) fn scope(scope: &str, details: bool) -> String {
    match scope {
        "machine:~" => "This computer and your projects".into(),
        "machine:~;no-personal-files" => {
            "This computer and your projects, personal folders skipped".into()
        }
        "repos:~" => "Your projects".into(),
        _ if details => scope.strip_prefix("repos:").unwrap_or(scope).to_owned(),
        _ if scope.starts_with("machine:") => "This computer".into(),
        _ => "Selected folders".into(),
    }
}

pub(super) fn command_purpose(command: &str) -> Option<&'static str> {
    [
        ("brew upgrade ", "update it with Homebrew"),
        ("mise upgrade ", "update it with mise"),
        ("mise install ", "install the fixed version with mise"),
        ("cargo update ", "update the project's Cargo lockfile"),
        ("npm install ", "install the fixed version with npm"),
        (
            "wpantry fix secret ",
            "walk you through removing the saved secret",
        ),
    ]
    .into_iter()
    .find_map(|(prefix, purpose)| command.starts_with(prefix).then_some(purpose))
}

/// A word in a fix command that Pantry can describe: letters, digits and
/// the punctuation package names and versions use. Never a quote, a shell
/// operator or a space.
fn plain_word(word: &str) -> bool {
    !word.is_empty()
        && word
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._@:/+-".contains(&b))
}

/// What a fix command will do, only when the whole command has exactly the
/// shape Pantry knows for that tool: the tool, its verb, this component
/// (and the fixed version, where the tool names one), and nothing else.
/// The scanner runs the command's words without a shell, so any extra word
/// is another package or argument, and the specific sentence would promise
/// less than the command does.
///
/// ```text
/// npm install left-pad@2.0                 -> install the fixed version with npm
/// npm install left-pad@2.0; touch marker   -> None
/// npm install left-pad@2.0 other           -> None
/// ```
pub(super) fn specific_purpose(finding: &Finding, command: &str) -> Option<(&'static str, bool)> {
    let name = finding.component.as_str();
    let fixed = finding.fixed.as_str();
    // Look-alike or non-ASCII names are shown, never vouched for.
    if !plain_word(name) {
        return None;
    }
    let words: Vec<&str> = command.split(' ').collect();
    if !words.iter().all(|w| plain_word(w)) {
        return None;
    }
    let spec = format!("{name}@{fixed}");
    let with_fixed = !fixed.is_empty() && plain_word(fixed);
    // (purpose, whether the command names the fixed version)
    match words.as_slice() {
        ["npm", "install", s] if with_fixed && *s == spec => {
            Some(("install the fixed version with npm", true))
        }
        ["mise", "install", s] if with_fixed && *s == spec => {
            Some(("install the fixed version with mise", true))
        }
        ["cargo", "update", "-p", n, "--precise", v] if *n == name && with_fixed && *v == fixed => {
            Some(("update the project's Cargo lockfile", true))
        }
        ["brew", "upgrade", n] | ["brew", "upgrade", "--cask", n] if *n == name => {
            Some(("update it with Homebrew", false))
        }
        ["mise", "upgrade", n] if *n == name || n.strip_prefix("brew:") == Some(name) => {
            Some(("update it with mise", false))
        }
        ["wpantry", "fix", "secret", id] if *id == finding.id => {
            Some(("walk you through removing the saved secret", false))
        }
        _ => None,
    }
}

/// One plain sentence for what a fix will do. The specific sentence needs
/// [`specific_purpose`]; anything else says only that one command runs,
/// and the command is shown beside it.
pub(super) fn fix_sentence(finding: &Finding, command: &str) -> String {
    let Some((purpose, names_fixed)) = specific_purpose(finding, command) else {
        return "Pantry will run one command.".into();
    };
    let name = finding.component.as_str();
    let target = match (finding.version.is_empty(), names_fixed) {
        (false, true) => format!(" from version {} to {}", finding.version, finding.fixed),
        (true, true) => format!(" to version {}", finding.fixed),
        _ => String::new(),
    };
    format!("Pantry will update {name}{target}. To do this it will {purpose}.")
}

/// How to open a terminal, for people who never have.
pub(super) fn terminal_step() -> &'static str {
    if cfg!(target_os = "macos") {
        "Open Terminal: press Command and Space together, type Terminal, then press Return."
    } else if cfg!(windows) {
        "Open Terminal: select Start, type Terminal, then press Enter."
    } else {
        "Open your Terminal app from the applications menu."
    }
}

pub(super) fn paste_step() -> &'static str {
    if cfg!(target_os = "macos") {
        "Choose Copy command below. In Terminal, press Command and V to paste it, then press Return."
    } else if cfg!(windows) {
        "Choose Copy command below. In Terminal, right-click to paste it, then press Enter."
    } else {
        "Choose Copy command below. In the terminal, press Ctrl, Shift and V to paste it, then press Enter."
    }
}

/// The longest advisory summary the detail card quotes, in characters.
const QUOTE_MAX: usize = 300;

/// An advisory's summary as the detail card quotes it: on one line, at
/// most [`QUOTE_MAX`] characters cut at a word, and with its own quote
/// marks turned into single ones so it cannot close the quote around it.
///
/// ```ignore
/// quoted_summary("Say \"hi\"\nnow") == "Say 'hi' now"
/// ```
pub fn quoted_summary(summary: &str) -> String {
    let flat: String = summary
        .chars()
        .map(|c| match c {
            '\u{201c}' | '\u{201d}' | '"' | '\u{201e}' | '\u{00ab}' | '\u{00bb}' => '\'',
            other => other,
        })
        .collect();
    one_line(&flat, QUOTE_MAX)
}

#[cfg(test)]
#[path = "text_tests.rs"]
mod tests;
