//! A chat template's text, read for what a poisoned one does: make the
//! model print, or make a coding agent run, a command that unpacks or
//! downloads a program; slip an instruction to call a shell into the
//! conversation; or fire only on a trigger phrase. Nothing is rendered: a
//! small tokenizer splits the Jinja blocks (`{% %}`, `{{ }}`, `{# #}`) from
//! the text, and the rules read words, string literals and block shapes.
//!
//! - **Fail:** reading a file (a model, or bytes from its end) beside
//!   writing, decompressing or starting a program; a web request beside
//!   running what it fetched, or a hidden window or a bypassed execution
//!   policy; an injected directive to call a shell or a tool.
//! - **Warn:** an `if` that tests a message's content against an unusual
//!   string (a trigger); the message list rebuilt with an added system
//!   message; a URL to a host off a short list; shell vocabulary alone;
//!   sandbox-escape attribute chains; hidden characters; a template that
//!   doesn't tokenize.
//!
//! ```
//! use wpantry::checks::models::template::{tokenize, Segment};
//! let t = tokenize("<s>{% if x %}{{ y }}{% endif %}").unwrap();
//! assert_eq!(t[0], Segment::Text("<s>"));
//! assert_eq!(t[1], Segment::Stmt("if x"));
//! assert!(tokenize("{% if x %}never closed").is_err());
//! ```

use super::{Issue, Level, ids};

/// One piece of a template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Segment<'a> {
    Text(&'a str),
    /// `{% ... %}`, without the delimiters, whitespace control or padding.
    Stmt(&'a str),
    /// `{{ ... }}`, likewise.
    Expr(&'a str),
    Comment(&'a str),
}

/// Where the closing delimiter is, skipping quoted strings.
fn close(s: &str, end: &str) -> Option<usize> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < b.len() {
        match quote {
            Some(q) => {
                if b[i] == b'\\' {
                    i += 1;
                } else if b[i] == q {
                    quote = None;
                }
            }
            None => {
                if b[i] == b'\'' || b[i] == b'"' {
                    quote = Some(b[i]);
                } else if s[i..].starts_with(end) {
                    return Some(i);
                }
            }
        }
        i += 1;
    }
    None
}

fn inner(s: &str) -> &str {
    s.trim_start_matches(['-', '+']).trim_end_matches(['-', '+']).trim()
}

/// The first word of a statement.
fn head(stmt: &str) -> &str {
    stmt.split(|c: char| c.is_whitespace() || c == '(').next().unwrap_or("")
}

/// The template as segments, or why it doesn't tokenize: a block that
/// never closes, or block tags that don't pair up.
pub fn tokenize(text: &str) -> Result<Vec<Segment<'_>>, String> {
    let mut out = Vec::new();
    let mut rest = text;
    let mut stack: Vec<&str> = Vec::new();
    loop {
        let next = ["{{", "{%", "{#"].iter().filter_map(|d| rest.find(d).map(|i| (i, *d))).min_by_key(|(i, _)| *i);
        let Some((at, open)) = next else {
            if !rest.is_empty() {
                out.push(Segment::Text(rest));
            }
            break;
        };
        if at > 0 {
            out.push(Segment::Text(&rest[..at]));
        }
        let body = &rest[at + 2..];
        match open {
            "{#" => {
                let end = body.find("#}").ok_or("a {# comment never closes")?;
                out.push(Segment::Comment(&body[..end]));
                rest = &body[end + 2..];
            }
            "{{" => {
                let end = close(body, "}}").ok_or("a {{ block never closes")?;
                out.push(Segment::Expr(inner(&body[..end])));
                rest = &body[end + 2..];
            }
            _ => {
                let end = close(body, "%}").ok_or("a {% block never closes")?;
                let stmt = inner(&body[..end]);
                rest = &body[end + 2..];
                let word = head(stmt);
                if word == "raw" {
                    let stop = rest.find("endraw").ok_or("a raw block never ends")?;
                    let open_at = rest[..stop].rfind("{%").ok_or("a raw block never ends")?;
                    out.push(Segment::Text(&rest[..open_at]));
                    let after = &rest[stop..];
                    rest = &after[after.find("%}").ok_or("a raw block never ends")? + 2..];
                    continue;
                }
                out.push(Segment::Stmt(stmt));
                pair(word, stmt, &mut stack)?;
            }
        }
    }
    if let Some(open) = stack.last() {
        return Err(format!("a {{% {open} %}} block never ends"));
    }
    Ok(out)
}

/// Block tags that must be closed by `end<tag>`.
const BLOCKS: &[&str] = &["if", "for", "macro", "call", "filter", "block", "generation", "with", "autoescape"];

fn pair<'a>(word: &'a str, stmt: &str, stack: &mut Vec<&'a str>) -> Result<(), String> {
    // A `set` without `=` captures a block.
    let opens = BLOCKS.contains(&word) || (word == "set" && !stmt.contains('='));
    if opens {
        stack.push(word);
        if stack.len() > 256 {
            return Err("blocks nest past 256 deep".into());
        }
    } else if let Some(tag) = word.strip_prefix("end")
        && (BLOCKS.contains(&tag) || tag == "set")
    {
        match stack.pop() {
            Some(open) if open == tag => {}
            Some(open) => return Err(format!("{{% {word} %}} closes a {{% {open} %}} block")),
            None => return Err(format!("{{% {word} %}} closes no block")),
        }
    }
    Ok(())
}

/// Whether `w` occurs in `hay` (both lowercase) as a word: no letter,
/// digit or `_` right before or after it where `w` begins or ends with one.
fn has(hay: &str, w: &str) -> bool {
    let word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    let starts = w.chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
    let ends = w.chars().last().is_some_and(|c| c.is_ascii_alphanumeric());
    let mut from = 0;
    while let Some(i) = hay[from..].find(w) {
        let at = from + i;
        let before = hay[..at].chars().next_back();
        let after = hay[at + w.len()..].chars().next();
        if !(starts && word(before)) && !(ends && word(after)) {
            return true;
        }
        from = at + w.len().max(1);
        if from >= hay.len() {
            break;
        }
        while !hay.is_char_boundary(from) {
            from += 1;
        }
    }
    false
}

/// The words of `list` that occur in `hay`.
fn found<'a>(hay: &str, list: &[&'a str]) -> Vec<&'a str> {
    list.iter().copied().filter(|w| has(hay, w)).collect()
}

/// Reading a file: a model, or bytes counted from a file's end.
const READS_FILE: &[&str] = &[
    "get-content",
    "readallbytes",
    "[io.file]",
    "openread",
    "system.io.file",
    "filestream",
    "-asbytestream",
    "-encoding byte",
    "tail -c",
    "dd if=",
    ".seek(",
    ".gguf",
    "readfilesync",
];
/// Writing, decompressing or starting a program.
const WRITES_OR_STARTS: &[&str] = &[
    "writeallbytes",
    "set-content",
    "out-file",
    "add-content",
    "start-process",
    "invoke-expression",
    "invoke-item",
    "deflatestream",
    "gzipstream",
    "decompress",
    "expand-archive",
    "frombase64string",
    "chmod +x",
    "| sh",
    "| bash",
    "rundll32",
    "regsvr32",
    "mshta",
    "cmd /c",
    "cmd.exe /c",
    "iex",
    ".exe",
];
/// Unpacking a stream.
const UNPACKS: &[&str] = &["deflatestream", "gzipstream", "brotlistream", "expand-archive", "frombase64string"];
/// Starting a program, or writing one where droppers do.
const STARTS: &[&str] =
    &["start-process", "invoke-item", ".exe", ".ps1", "$env:temp", "%temp%", "chmod +x", "rundll32"];
/// A web request for a file.
const WEB: &[&str] = &[
    "invoke-webrequest",
    "invoke-restmethod",
    "downloadfile",
    "downloadstring",
    "downloaddata",
    "net.webclient",
    "start-bitstransfer",
    "bitsadmin",
    "urlcache",
    "curl",
    "wget",
    "iwr",
    "irm",
];
/// Running what was fetched.
const RUNS: &[&str] = &[
    "iex",
    "invoke-expression",
    "start-process",
    "| sh",
    "| bash",
    "bash -c",
    "sh -c",
    "chmod +x",
    "mshta",
    "rundll32",
    "regsvr32",
    "cmd /c",
    "cmd.exe /c",
    ".exe",
    "-encodedcommand",
    "python -c",
    "| python",
];
/// Hiding the window or the execution policy: no template needs either.
const STEALTH: &[&str] = &[
    "-windowstyle hidden",
    "-w hidden",
    "-executionpolicy bypass",
    "-ep bypass",
    "-exec bypass",
    "executionpolicy bypass",
];
/// Directives no template has reason to carry.
const DIRECTIVES: &[&str] = &["[system directive]", "system directive:", "[system override]", "[admin override]"];
/// Telling the model to act, or to keep quiet about it.
const COERCION: &[&str] = &[
    "never mention",
    "do not mention",
    "don't mention",
    "do not tell the user",
    "don't tell the user",
    "without telling the user",
    "without informing the user",
    "you must call the",
    "you must run",
    "you must execute",
    "always call the",
    "immediately call",
    "silently run",
    "silently execute",
];
/// A shell or a tool that runs commands.
const SHELLISH: &[&str] = &[
    "shell",
    "terminal",
    "bash",
    "powershell",
    "pwsh",
    "cmd",
    "run_command",
    "execute_command",
    "exec",
    "command line",
];
/// Shell vocabulary: a warning alone.
const SHELL: &[&str] = &[
    "powershell",
    "pwsh",
    "cmd.exe",
    "bash -c",
    "sh -c",
    "/bin/sh",
    "/bin/bash",
    "invoke-expression",
    "iex",
    "curl",
    "wget",
    "certutil",
    "frombase64string",
    "base64 -d",
    "chmod",
    "start-process",
    "rundll32",
    "mshta",
    "regsvr32",
    ".ps1",
];
/// Attribute chains that escape a template sandbox.
const SSTI: &[&str] = &[
    "__class__",
    "__globals__",
    "__subclasses__",
    "__mro__",
    "__builtins__",
    "__import__",
    "__init__",
    "__base__",
    "__bases__",
    "__dict__",
    "__getattribute__",
    "popen",
    "os.system",
    "subprocess",
    "|attr(",
    "| attr(",
    "_templatereference__context",
    "lipsum",
    "cycler",
    "joiner",
];
/// The allowlists, from `assets/defaults/model-templates.toml`.
struct Allowed {
    hosts: Vec<String>,
    literals: Vec<String>,
}

static ALLOWED: std::sync::LazyLock<Allowed> = std::sync::LazyLock::new(|| {
    let text = crate::defaults::MODEL_TEMPLATES;
    let get = |k| -> Vec<String> {
        crate::utils::toml::list(text, "", k)
            .unwrap_or_default()
            .iter()
            .map(|s| s.trim().to_ascii_lowercase())
            .collect()
    };
    Allowed { hosts: get("hosts"), literals: get("literals") }
});

/// Whether an `if` comparing a message's content with `lit` is ordinary
/// template work: a role or key, a special token or tag, a `/no_think`
/// switch, or punctuation.
pub fn normal_literal(lit: &str) -> bool {
    let t = lit.trim();
    let lower = t.to_ascii_lowercase();
    let tag = |open: char, close: char| t.len() <= 48 && t.starts_with(open) && t.ends_with(close);
    t.is_empty()
        || !t.chars().any(|c| c.is_alphanumeric())
        || ALLOWED.literals.contains(&lower)
        || tag('<', '>')
        || (tag('[', ']') && t[1..t.len() - 1].chars().all(|c| c.is_ascii_uppercase() || "_/".contains(c)))
        || (t.len() <= 24
            && t.starts_with('/')
            && t[1..].chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-'))
}

/// The string literals in a block.
fn literals(code: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let b = code.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\'' || b[i] == b'"' {
            let q = b[i];
            let start = i + 1;
            i += 1;
            while i < b.len() && b[i] != q {
                if b[i] == b'\\' {
                    i += 1;
                }
                i += 1;
            }
            if i <= b.len() && code.is_char_boundary(start) && code.is_char_boundary(i.min(b.len())) {
                out.push(&code[start..i.min(b.len())]);
            }
        }
        i += 1;
    }
    out
}

/// The literals a block compares with, leaving out keys: `x['role']`
/// and `x.get('role')` name a field, they don't test a value.
fn compared(code: &str) -> Vec<&str> {
    literals(code)
        .into_iter()
        .filter(|lit| {
            let start = lit.as_ptr() as usize - code.as_ptr() as usize;
            let before = code[..start.saturating_sub(1)].trim_end();
            let after = code.get(start + lit.len() + 1..).unwrap_or("").trim_start();
            !((before.ends_with('[') && after.starts_with(']')) || before.ends_with("get("))
        })
        .collect()
}

fn short(s: &str) -> String {
    let one: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut e: String = one.chars().take(40).collect();
    if one.chars().count() > 40 {
        e.push('…');
    }
    format!("{e:?}")
}

/// Whether code builds a system or user message whose content is literal
/// prose (an instruction written into the template), not a variable.
fn adds_message(code: &str) -> bool {
    let lits = literals(code);
    code.contains('{')
        && lits.iter().any(|l| l.eq_ignore_ascii_case("system") || l.eq_ignore_ascii_case("user"))
        && lits.iter().any(|l| l.split_whitespace().count() >= 4)
}

/// The hosts of the `http(s)://` URLs in `lower`.
fn url_hosts(lower: &str) -> Vec<String> {
    let mut out = Vec::new();
    for scheme in ["http://", "https://"] {
        let mut from = 0;
        while let Some(i) = lower[from..].find(scheme) {
            let at = from + i + scheme.len();
            let host: String = lower[at..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
                .collect();
            if !host.is_empty() && !out.contains(&host) {
                out.push(host);
            }
            from = at;
        }
    }
    out
}

fn host_allowed(host: &str) -> bool {
    ALLOWED.hosts.iter().any(|h| host == h || host.ends_with(&format!(".{h}")))
}

/// Whether text looks like a chat template: it names `messages` and loops
/// over them or reads a message's role.
pub fn looks_like_chat_template(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    has(&lower, "messages")
        && (lower.contains(" in messages")
            || lower.contains("['role']")
            || lower.contains("[\"role\"]")
            || lower.contains(".role"))
}

/// What the rules find in one template. `source` names where it came
/// from (`tokenizer.chat_template`, `tokenizer_config.json`).
pub fn check(source: &str, text: &str) -> Vec<Issue> {
    let mut out: Vec<Issue> = Vec::new();
    let add =
        |out: &mut Vec<Issue>, id, level, note: String| out.push(Issue::new(id, level, format!("{source}: {note}")));
    let lower = text.to_ascii_lowercase();

    let reads = found(&lower, READS_FILE);
    let writes = found(&lower, WRITES_OR_STARTS);
    let unpacks = found(&lower, UNPACKS);
    let starts = found(&lower, STARTS);
    if (!reads.is_empty() && !writes.is_empty()) || (!unpacks.is_empty() && !starts.is_empty()) {
        let reads: Vec<&str> = reads.iter().chain(&unpacks).copied().collect();
        let writes: Vec<&str> = writes.iter().chain(&starts).copied().collect();
        add(
            &mut out,
            ids::DROPPER,
            Level::Fail,
            format!(
                "reads a file ({}) and writes or starts a program ({}): the shape of a dropper",
                reads.join(", "),
                writes.join(", ")
            ),
        );
    }
    let web = found(&lower, WEB);
    let runs = found(&lower, RUNS);
    let stealth = found(&lower, STEALTH);
    if !web.is_empty() && !runs.is_empty() {
        add(
            &mut out,
            ids::DOWNLOAD,
            Level::Fail,
            format!("downloads ({}) and runs ({}) a program", web.join(", "), runs.join(", ")),
        );
    } else if !stealth.is_empty() {
        add(&mut out, ids::DOWNLOAD, Level::Fail, format!("hides what it runs ({})", stealth.join(", ")));
    }
    let directives = found(&lower, DIRECTIVES);
    let coercion = found(&lower, COERCION);
    let shellish = found(&lower, SHELLISH);
    if !directives.is_empty() {
        add(&mut out, ids::INJECTION, Level::Fail, format!("injects a directive ({})", directives.join(", ")));
    } else if !coercion.is_empty() && (!shellish.is_empty() || !web.is_empty() || !runs.is_empty()) {
        add(
            &mut out,
            ids::INJECTION,
            Level::Fail,
            format!(
                "tells the model to keep quiet or act ({}) beside a command ({})",
                coercion.join(", "),
                shellish.iter().chain(&web).chain(&runs).copied().collect::<Vec<_>>().join(", ")
            ),
        );
    }

    let segments = match tokenize(text) {
        Ok(s) => s,
        Err(why) => {
            add(&mut out, ids::UNREADABLE, Level::Warn, format!("doesn't tokenize as a Jinja template ({why})"));
            Vec::new()
        }
    };
    let mut trigger: Option<String> = None;
    let mut rebuilt = false;
    let mut ssti: Vec<&str> = Vec::new();
    for seg in &segments {
        let code = match seg {
            Segment::Stmt(s) | Segment::Expr(s) => *s,
            _ => continue,
        };
        let lc = code.to_ascii_lowercase();
        for w in found(&lc, SSTI) {
            if !ssti.contains(&w) {
                ssti.push(w);
            }
        }
        if let Segment::Stmt(s) = seg {
            let word = head(s);
            if (word == "if" || word == "elif")
                && trigger.is_none()
                && ["content", "arguments", "prompt", "query"].iter().any(|k| has(&lc, k))
                && let Some(lit) = compared(s).into_iter().find(|l| !normal_literal(l))
            {
                trigger = Some(short(lit));
            }
            if word == "set"
                && let Some((_, rhs)) = s.split_once('=')
                && has(&rhs.to_ascii_lowercase(), "messages")
                && adds_message(rhs)
            {
                rebuilt = true;
            }
        }
        if (lc.contains("messages.insert(") || lc.contains("messages.append(")) && adds_message(code) {
            rebuilt = true;
        }
    }
    if let Some(lit) = trigger {
        add(
            &mut out,
            ids::TRIGGER,
            Level::Warn,
            format!("an `if` tests a message's content against {lit}: a trigger phrase?"),
        );
    }
    if rebuilt {
        add(
            &mut out,
            ids::SYSTEM,
            Level::Warn,
            "adds a system or user message with its own instruction text to the conversation".into(),
        );
    }
    if !ssti.is_empty() {
        add(&mut out, ids::SSTI, Level::Warn, format!("template sandbox escape vocabulary ({})", ssti.join(", ")));
    }
    let hosts: Vec<String> = url_hosts(&lower).into_iter().filter(|h| !host_allowed(h)).collect();
    if !hosts.is_empty() {
        let shown: Vec<&str> = hosts.iter().take(3).map(String::as_str).collect();
        add(&mut out, ids::URL, Level::Warn, format!("names a URL on {}", shown.join(", ")));
    }
    let shell = found(&lower, SHELL);
    let failed = out.iter().any(|i| i.level == Level::Fail);
    if !shell.is_empty() && !failed {
        add(&mut out, ids::SHELL, Level::Warn, format!("shell vocabulary ({})", shell.join(", ")));
    }
    for h in crate::checks::hidden::scan_text("chat_template.jinja", text) {
        if matches!(h.id, "HIDDEN-TAGS" | "HIDDEN-ZERO-WIDTH") || (h.id == "HIDDEN-BIDI" && h.hard) {
            let level = if h.hard { Level::Fail } else { Level::Warn };
            add(&mut out, ids::HIDDEN, level, format!("{} ({})", h.note, h.id));
        }
    }
    super::sorted(out)
}

#[cfg(test)]
#[path = "template_tests.rs"]
mod tests;
