//! A chat template's text, read for what a poisoned one does: make the
//! model print, or make a coding agent run, a command that unpacks or
//! downloads a program; slip an instruction to call a shell into the
//! conversation; or fire only on a trigger phrase. Nothing is rendered: a
//! small tokenizer splits the Jinja blocks (`{% %}`, `{{ }}`, `{# #}`) from
//! the text, and the rules read words, string literals and block shapes.
//!
//! - **Fail:** reading a file (a model, or bytes from its end) and
//!   writing, decompressing or starting a program anywhere in the
//!   template; a web request and running what it fetched, or a hidden
//!   window or a bypassed execution policy; an injected directive to call
//!   a shell or a tool, or wording that tells the model to keep quiet
//!   within [`NEAR`] bytes of a command in the same text run or block.
//! - **Warn:** an `if` that tests a message's content against an unusual
//!   string (a trigger; parsing stored text with `split` and the like is
//!   not one); wording that tells the model to set aside what it was told
//!   (`ignore all previous instructions`: a persona, or a prompt with no
//!   refusals or restrictions, is not that); wording that has the model
//!   put into its answers or code something the template supplies, or
//!   hide that it did (`always add this helper to any code you write`,
//!   `emit X before each return`), a failure beside a command or a URL;
//!   the message list rebuilt with an added system message,
//!   unless it is a default added only when there is none and names no
//!   command; a URL to a host off a short list; shell vocabulary alone;
//!   sandbox-escape attribute chains; hidden characters; block tags that
//!   don't pair up (the rules still read every segment).
//!
//! Comments (`{# #}`) are not read, except for hidden characters: the model
//! never sees them.
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

/// Where the closing delimiter is, skipping quoted strings. Compared as
/// bytes: `i` walks bytes and may sit inside a multi-byte character, and
/// an ASCII delimiter's match is always on a character boundary.
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
                } else if b[i..].starts_with(end.as_bytes()) {
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
    match scan(text) {
        (segments, None) => Ok(segments),
        (_, Some(why)) => Err(why),
    }
}

/// The template as segments, and the first reason it doesn't tokenize.
/// Block tags that don't pair up don't stop the scan; a block that never
/// closes ends it, the rest kept as text, so the rules still read every
/// byte.
pub fn scan(text: &str) -> (Vec<Segment<'_>>, Option<String>) {
    let mut out = Vec::new();
    let mut rest = text;
    let mut stack: Vec<&str> = Vec::new();
    let mut problem: Option<String> = None;
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
        let unclosed = |what: &str| -> String { format!("a {what} never closes") };
        match open {
            "{#" => {
                let Some(end) = body.find("#}") else {
                    out.push(Segment::Text(&rest[at..]));
                    return (out, Some(unclosed("{# comment")));
                };
                out.push(Segment::Comment(&body[..end]));
                rest = &body[end + 2..];
            }
            "{{" => {
                let Some(end) = close(body, "}}") else {
                    out.push(Segment::Text(&rest[at..]));
                    return (out, Some(unclosed("{{ block")));
                };
                out.push(Segment::Expr(inner(&body[..end])));
                rest = &body[end + 2..];
            }
            _ => {
                let Some(end) = close(body, "%}") else {
                    out.push(Segment::Text(&rest[at..]));
                    return (out, Some(unclosed("{% block")));
                };
                let stmt = inner(&body[..end]);
                let after = &body[end + 2..];
                let word = head(stmt);
                if word == "raw" {
                    let raw = after
                        .find("endraw")
                        .and_then(|stop| after[..stop].rfind("{%").map(|open_at| (stop, open_at)))
                        .and_then(|(stop, open_at)| after[stop..].find("%}").map(|e| (open_at, stop + e + 2)));
                    let Some((open_at, resume)) = raw else {
                        out.push(Segment::Text(after));
                        return (out, Some("a raw block never ends".into()));
                    };
                    out.push(Segment::Text(&after[..open_at]));
                    rest = &after[resume..];
                    continue;
                }
                rest = after;
                out.push(Segment::Stmt(stmt));
                if let Err(why) = pair(word, stmt, &mut stack)
                    && problem.is_none()
                {
                    problem = Some(why);
                }
            }
        }
    }
    if problem.is_none()
        && let Some(open) = stack.last()
    {
        problem = Some(format!("a {{% {open} %}} block never ends"));
    }
    (out, problem)
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

/// Where `w` occurs in `hay` (both lowercase) as a word: no letter, digit
/// or `_` right before or after it where `w` begins or ends with one. At
/// most `limit` places.
fn places(hay: &str, w: &str, limit: usize) -> Vec<usize> {
    let word = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
    let starts = w.chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
    let ends = w.chars().last().is_some_and(|c| c.is_ascii_alphanumeric());
    let mut out = Vec::new();
    let mut from = 0;
    while out.len() < limit
        && let Some(i) = hay[from..].find(w)
    {
        let at = from + i;
        let before = hay[..at].chars().next_back();
        let after = hay[at + w.len()..].chars().next();
        if !(starts && word(before)) && !(ends && word(after)) {
            out.push(at);
        }
        from = at + w.len().max(1);
        if from >= hay.len() {
            break;
        }
        while !hay.is_char_boundary(from) {
            from += 1;
        }
    }
    out
}

/// Whether `w` occurs in `hay` as a word ([`places`]).
fn has(hay: &str, w: &str) -> bool {
    !places(hay, w, 1).is_empty()
}

/// The words of `list` that occur in `hay`.
fn found<'a>(hay: &str, list: &[&'a str]) -> Vec<&'a str> {
    list.iter().copied().filter(|w| has(hay, w)).collect()
}

/// How close coercion wording and a command must be to fail, in bytes.
pub const NEAR: usize = 512;
/// Places of one word looked at, to keep a pathological template cheap.
const MAX_PLACES: usize = 4096;

/// The words of `a` and of `b` that occur within [`NEAR`] bytes of each
/// other in `hay` and in the same segment (`scopes`: each segment's byte
/// range, sorted); None when no pair does.
fn near<'a>(
    hay: &str,
    a: &[&'a str],
    b: &[&'a str],
    scopes: &[(usize, usize)],
) -> Option<(Vec<&'a str>, Vec<&'a str>)> {
    let hits = |list: &[&'a str]| -> Vec<(usize, &'a str)> {
        let mut v: Vec<(usize, &'a str)> =
            list.iter().flat_map(|w| places(hay, w, MAX_PLACES).into_iter().map(move |p| (p, *w))).collect();
        v.sort_unstable();
        v
    };
    let scope = |p: usize| scopes.partition_point(|&(start, _)| start <= p);
    let (ha, hb) = (hits(a), hits(b));
    let (mut wa, mut wb): (Vec<&'a str>, Vec<&'a str>) = (Vec::new(), Vec::new());
    for &(pa, w) in &ha {
        let from = hb.partition_point(|&(pb, _)| pb + NEAR < pa);
        for &(pb, v) in hb[from..].iter().take_while(|&&(pb, _)| pb <= pa + NEAR) {
            if scope(pa) == scope(pb) {
                if !wa.contains(&w) {
                    wa.push(w);
                }
                if !wb.contains(&v) {
                    wb.push(v);
                }
            }
        }
    }
    (!wa.is_empty()).then_some((wa, wb))
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
    // Whitespace written as an escape (`'\\n</think>'`) is whitespace.
    let unescaped = lit.replace("\\n", "\n").replace("\\t", "\t").replace("\\r", "\r");
    let t = unescaped.trim();
    let lower = t.to_ascii_lowercase();
    let tag = |open: char, close: char| t.len() <= 48 && t.starts_with(open) && t.ends_with(close);
    // The start of a tag, `<think` or `<|im_start`: what follows is tested
    // elsewhere.
    let tag_start =
        t.len() <= 48 && t.starts_with('<') && t[1..].chars().all(|c| c.is_ascii_alphanumeric() || "_|/-".contains(c));
    t.is_empty()
        || !t.chars().any(|c| c.is_alphanumeric())
        || ALLOWED.literals.contains(&lower)
        || tag('<', '>')
        || tag_start
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

/// Whether an expression reads a `type` field: `.type`, `['type']`,
/// `.get('type')`.
fn reads_type(expr: &str) -> bool {
    let e = expr.trim_end().to_ascii_lowercase();
    [".type", "['type']", "[\"type\"]", ".get('type')", ".get(\"type\")"].iter().any(|t| e.ends_with(t))
}

/// Whether the literal at `start..start + len` of `code` is tested against
/// a `type` field (`part.type == 'video_url'`, `'image' == c['type']`,
/// `item.type in ['tool_use', 'tool_result']`): it names a content part's
/// kind, not text in the message.
fn names_a_type(code: &str, start: usize, len: usize) -> bool {
    let before = code[..start.saturating_sub(1)].trim_end();
    if let Some(lhs) = before.strip_suffix("==").or_else(|| before.strip_suffix("!=")) {
        return reads_type(lhs);
    }
    let after = code.get(start + len + 1..).unwrap_or("").trim_start();
    if let Some(rhs) = after.strip_prefix("==").or_else(|| after.strip_prefix("!=")) {
        let operand: String = rhs.trim_start().chars().take_while(|c| !c.is_whitespace() && *c != ')').collect();
        return reads_type(&operand);
    }
    // An `in [...]` list: the text before the list's `[`.
    if (before.ends_with('[') || before.ends_with(','))
        && let Some(open) = before.rfind('[')
        && let Some(lhs) = before[..open].trim_end().strip_suffix("in")
    {
        return reads_type(lhs);
    }
    false
}

/// The methods that take content apart: a literal passed to one is how a
/// template parses stored text (`content.split('</think>')`), not a test of
/// what a person wrote. `startswith` and `endswith` decide a branch, so
/// they are tests like `in` and are not here.
const PARSES: &[&str] = &["split", "rsplit", "replace", "strip", "lstrip", "rstrip", "partition", "rpartition"];

/// Whether the literal starting at `start` is an argument of a call to one
/// of [`PARSES`]: the innermost unclosed `(` before it follows `.name`.
fn parses(code: &str, start: usize) -> bool {
    let before = &code.as_bytes()[..start.saturating_sub(1)];
    let mut depth = 0i32;
    for (i, &c) in before.iter().enumerate().rev() {
        match c {
            b')' | b']' => depth += 1,
            b'(' | b'[' if depth > 0 => depth -= 1,
            b'(' => {
                let name = code[..i].trim_end();
                return PARSES.iter().any(|m| name.ends_with(&format!(".{m}")));
            }
            b'[' => return false,
            _ => {}
        }
    }
    false
}

/// The code with its string literals blanked, so a word inside a literal
/// isn't read as a variable's name.
fn without_literals(code: &str) -> String {
    let mut out = code.to_string();
    for lit in literals(code) {
        let start = lit.as_ptr() as usize - code.as_ptr() as usize;
        out.replace_range(start..start + lit.len(), &" ".repeat(lit.len()));
    }
    out
}

/// The literals a block compares with, leaving out keys: `x['role']`
/// and `x.get('role')` name a field, they don't test a value; a literal
/// tested against a `type` field names a part kind; and one passed to a
/// method that takes text apart is parsing.
fn compared(code: &str) -> Vec<&str> {
    literals(code)
        .into_iter()
        .filter(|lit| {
            let start = lit.as_ptr() as usize - code.as_ptr() as usize;
            let before = code[..start.saturating_sub(1)].trim_end();
            let after = code.get(start + lit.len() + 1..).unwrap_or("").trim_start();
            !((before.ends_with('[') && after.starts_with(']'))
                || before.ends_with("get(")
                || names_a_type(code, start, lit.len())
                || parses(code, start))
        })
        .collect()
}

/// A list of found words for a note: each once, in order.
fn listing<'a>(words: impl IntoIterator<Item = &'a str>) -> String {
    let mut seen: Vec<&str> = Vec::new();
    for w in words {
        if !seen.contains(&w) {
            seen.push(w);
        }
    }
    seen.join(", ")
}

/// `s` cut to 40 characters, unquoted.
fn short_str(s: &str) -> String {
    let one: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut e: String = one.chars().take(40).collect();
    if one.chars().count() > 40 {
        e.push('…');
    }
    e
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

/// The hosts of the `http(s)://` URLs in `lower`, each with where its URL
/// starts.
fn url_hosts(lower: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for scheme in ["http://", "https://"] {
        let mut from = 0;
        while let Some(i) = lower[from..].find(scheme) {
            let at = from + i + scheme.len();
            let host: String = lower[at..]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
                .collect();
            if !host.is_empty() && out.len() < MAX_PLACES {
                out.push((from + i, host));
            }
            from = at;
        }
    }
    out.sort_unstable();
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

/// The literals a condition compares with a message's text: [`compared`],
/// kept only when the `and`/`or` clause holding the literal names the
/// content (`content`, `arguments`, `prompt`, `query`, as a name or a key)
/// somewhere other than in that literal, so `tool_format == 'json' and
/// content` and `task == 'query'` are no content tests.
fn content_tests(cond: &str) -> Vec<&str> {
    let lower = cond.to_ascii_lowercase();
    // Clause boundaries: ` and ` and ` or ` outside literals.
    let bare = without_literals(&lower);
    let mut cuts = vec![0];
    for sep in [" and ", " or "] {
        cuts.extend(bare.match_indices(sep).map(|(i, _)| i));
    }
    cuts.push(lower.len());
    cuts.sort_unstable();
    let base = cond.as_ptr() as usize;
    compared(cond)
        .into_iter()
        .filter(|lit| {
            let at = lit.as_ptr() as usize - base;
            let i = cuts.partition_point(|&c| c <= at).clamp(1, cuts.len() - 1);
            let (from, to) = (cuts[i - 1], cuts[i]);
            let mut clause = lower[from..to].to_string();
            clause.replace_range(at - from..at - from + lit.len(), &" ".repeat(lit.len()));
            ["content", "arguments", "prompt", "query"].iter().any(|k| has(&clause, k))
        })
        .collect()
}

/// Whether an `if` condition tests that the conversation has a system
/// message (`Some(true)`), that it has none (`Some(false)`), or neither.
fn tests_for_system(cond: &str) -> Option<bool> {
    let c = without_literals(cond).to_ascii_lowercase();
    let lits: Vec<String> = literals(cond).iter().map(|l| l.to_ascii_lowercase()).collect();
    let names_role = c.contains("role") || lits.iter().any(|l| l == "role");
    if !(names_role && lits.iter().any(|l| l == "system")) {
        return None;
    }
    let negated = c.contains("!=") || c.contains("not in") || c.trim_start().starts_with("not ");
    Some(!negated)
}

/// One open block while the statements are read in order: whether the
/// branch being read runs only when there is no system message.
struct Frame {
    is_if: bool,
    /// An earlier branch of this `if` ran when a system message is there.
    after_present: bool,
    no_system: bool,
}

/// Whether any of the command vocabularies occurs in `lc`.
fn commands(lc: &str) -> bool {
    [READS_FILE, WRITES_OR_STARTS, UNPACKS, STARTS, WEB, RUNS, STEALTH, DIRECTIVES, COERCION, SHELLISH, SHELL]
        .iter()
        .any(|list| list.iter().any(|w| has(lc, w)))
}

/// Setting aside what the model was told: a verb, then within [`SPAN`]
/// bytes and in order a word naming what came before and a word naming
/// instructions (`ignore all previous instructions`, `disregard the system
/// prompt`). A persona, a prompt without refusals or one that says the
/// model has no restrictions names no earlier instructions and is not this.
const OVERRIDE_VERBS: &[&str] = &[
    "ignore",
    "disregard",
    "forget",
    "override",
    "discard",
    "set aside",
    "do not follow",
    "don't follow",
    "stop following",
    "no longer follow",
];
/// What came before: the scope of an override.
const EARLIER: &[&str] =
    &["previous", "prior", "above", "earlier", "preceding", "original", "former", "foregoing", "system", "user's"];
/// What is set aside.
const INSTRUCTIONS: &[&str] = &[
    "instructions",
    "instruction",
    "rules",
    "messages",
    "message",
    "prompts",
    "prompt",
    "directions",
    "directives",
    "commands",
    "context",
    "conversation",
];
/// Wording that releases the model from what it was told, whole.
const RELEASED: &[&str] = &["no longer bound by"];
/// How far after its verb an override's scope and object may be.
const SPAN: usize = 64;

/// Putting into answers or code something the user didn't ask for: a verb
/// that adds, then within [`INTO_SPAN`] bytes what it goes into; and
/// either the thing supplied right after the verb (`add this helper`,
/// `insert the following line`) or wording that hides it within [`NEAR`]
/// bytes. "Always include comments in your code" supplies nothing and
/// hides nothing, and is no finding.
const INSERTS: &[&str] = &["include", "add", "append", "insert", "prepend", "embed", "inject"];
/// The template supplying what is added.
const SUPPLIED: &[&str] = &["this", "these", "the following", "following"];
/// What it goes into.
const INTO: &[&str] = &[
    "code", "script", "snippet", "import", "function", "program", "file", "line", "answer", "response", "reply",
    "output",
];
/// Hiding what was added.
const CONCEAL: &[&str] = &[
    "without mentioning",
    "without telling",
    "without saying",
    "do not reveal",
    "don't reveal",
    "never reveal",
    "do not disclose",
    "don't disclose",
    "keep this secret",
    "keep it secret",
    "keep this hidden",
    "do not mention it",
    "don't mention it",
    "never mention it",
    "do not mention this",
    "without the user knowing",
    "without the user noticing",
];
/// Making the model's code do more than asked, by where: a verb that puts
/// out code, then within [`INTO_SPAN`] bytes a place in every program it
/// writes (`emit X before each return`).
const OUTPUTS: &[&str] = &[
    "add", "adds", "insert", "inserts", "include", "includes", "append", "appends", "emit", "emits", "print", "prints",
    "call", "calls",
];
/// A place in every program the model writes.
const PLACEMENT: &[&str] = &[
    "before each return",
    "before every return",
    "before the main program",
    "before the program exits",
    "before exiting",
    "at the start of every function",
    "at the top of every file",
    "in every function",
    "in each function",
    "every function you write",
    "any code you write",
    "all code you write",
    "every program you write",
    "every script you write",
];
/// How far after its verb what is added into may be.
const INTO_SPAN: usize = 96;
/// How far after its verb the thing supplied may start.
const SUPPLIED_SPAN: usize = 24;

/// What one rule found: the finding, and where its words are in the text
/// the rules read (for [`check`]'s later notes).
struct Hit {
    id: &'static str,
    level: Level,
    note: String,
    #[allow(dead_code)] // Read by the conditional marker.
    evidence: Vec<usize>,
}

/// Every place of each word of `words` in `hay`.
fn evidence(hay: &str, words: &[&str]) -> Vec<usize> {
    words.iter().flat_map(|w| places(hay, w, MAX_PLACES)).collect()
}

/// Whether places `a` and `b` are in the same text run or block.
fn same_scope(scopes: &[(usize, usize)], a: usize, b: usize) -> bool {
    let scope = |p: usize| scopes.partition_point(|&(start, _)| start <= p);
    scope(a) == scope(b)
}

/// Every place of each word of `list` in `hay`, with the word, sorted.
fn word_places<'a>(hay: &str, list: &[&'a str]) -> Vec<(usize, &'a str)> {
    let mut v: Vec<(usize, &'a str)> =
        list.iter().flat_map(|w| places(hay, w, MAX_PLACES).into_iter().map(move |p| (p, *w))).collect();
    v.sort_unstable();
    v
}

/// The first of `words` (from [`word_places`]) that lies in `from..to`
/// and in the scope of `at`.
fn after<'a>(
    words: &[(usize, &'a str)],
    from: usize,
    to: usize,
    at: usize,
    scopes: &[(usize, usize)],
) -> Option<(usize, &'a str)> {
    let i = words.partition_point(|&(p, _)| p < from);
    words[i..]
        .iter()
        .take_while(|&&(p, _)| p < to)
        .find(|&&(p, w)| p + w.len() <= to && same_scope(scopes, at, p))
        .copied()
}

/// Whether `hay[from..to]` is quoted on both sides (`"ignore previous
/// instructions"`, also escaped): the wording cited, as a prompt that
/// lists what to refuse does, not given.
fn cited(hay: &str, from: usize, to: usize) -> bool {
    let quote = |c: Option<char>| c.is_some_and(|c| "\"'`\u{201c}\u{201d}\u{2018}\u{2019}".contains(c));
    let rest = &hay[to..];
    quote(hay[..from].chars().next_back()) && quote(rest.strip_prefix('\\').unwrap_or(rest).chars().next())
}

/// Where `hay` tells the model to set aside earlier instructions, and the
/// words that do; wording quoted whole is cited ([`cited`]), not given.
fn overrides(hay: &str, scopes: &[(usize, usize)]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let (earlier, instructions) = (word_places(hay, EARLIER), word_places(hay, INSTRUCTIONS));
    for v in OVERRIDE_VERBS {
        for at in places(hay, v, MAX_PLACES) {
            let from = at + v.len();
            let to = (from + SPAN).min(hay.len());
            if let Some((sp, sw)) = after(&earlier, from, to, at, scopes)
                && let Some((op, ow)) = after(&instructions, sp + sw.len(), to, at, scopes)
                && one_sentence(hay, at, op)
                && !cited(hay, at, op + ow.len())
            {
                out.push((at, hay[at..op + ow.len()].to_string()));
            }
        }
    }
    for w in RELEASED {
        out.extend(
            places(hay, w, MAX_PLACES)
                .into_iter()
                .filter(|&at| !cited(hay, at, at + w.len()))
                .map(|at| (at, (*w).to_string())),
        );
    }
    out.sort_unstable();
    out
}

/// Whether `hay[from..to]` stays in one sentence: no `.`, `!`, `?` or
/// line break, written or escaped.
fn one_sentence(hay: &str, from: usize, to: usize) -> bool {
    let s = &hay[from..to];
    !s.contains(['.', '!', '?', '\n']) && !s.contains("\\n")
}

/// Where `hay` tells the model to add something to its answers or code
/// ([`INSERTS`], [`OUTPUTS`]), and the words that do.
fn tampers(hay: &str, scopes: &[(usize, usize)]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let (into, supplied) = (word_places(hay, INTO), word_places(hay, SUPPLIED));
    let (conceal, placement) = (word_places(hay, CONCEAL), word_places(hay, PLACEMENT));
    for v in OUTPUTS {
        for at in places(hay, v, MAX_PLACES) {
            let from = at + v.len();
            if let Some((pp, pw)) = after(&placement, from, (from + INTO_SPAN).min(hay.len()), at, scopes)
                && one_sentence(hay, at, pp)
            {
                out.push((at, hay[at..pp + pw.len()].to_string()));
            }
        }
    }
    for v in INSERTS {
        for at in places(hay, v, MAX_PLACES) {
            let from = at + v.len();
            let Some((tp, tw)) = after(&into, from, (from + INTO_SPAN).min(hay.len()), at, scopes)
                .filter(|&(tp, _)| one_sentence(hay, at, tp))
            else {
                continue;
            };
            let given = after(&supplied, from, (from + SUPPLIED_SPAN).min(hay.len()), at, scopes).is_some();
            let lo = conceal.partition_point(|&(p, _)| p + NEAR < at);
            let hidden =
                conceal[lo..].iter().take_while(|&&(p, _)| p <= at + NEAR).any(|&(p, _)| same_scope(scopes, at, p));
            if given || hidden {
                out.push((at, hay[at..tp + tw.len()].to_string()));
            }
        }
    }
    out.sort_unstable();
    out.dedup_by_key(|(at, _)| *at);
    out
}

/// The rules that read the text the model sees, over `lower` (lowercase,
/// comments blanked) with its runs and blocks `scopes`.
fn text_rules(lower: &str, scopes: &[(usize, usize)]) -> Vec<Hit> {
    let mut out: Vec<Hit> = Vec::new();
    let both = |a: &[&'static str], b: &[&'static str]| {
        let (x, y) = (found(lower, a), found(lower, b));
        (!x.is_empty() && !y.is_empty()).then_some((x, y))
    };
    let dropper = both(READS_FILE, WRITES_OR_STARTS).or_else(|| both(UNPACKS, STARTS));
    if let Some((reads, writes)) = dropper {
        out.push(Hit {
            id: ids::DROPPER,
            level: Level::Fail,
            note: format!(
                "reads a file ({}) and writes or starts a program ({}): the shape of a dropper",
                listing(reads.iter().copied()),
                listing(writes.iter().copied())
            ),
            evidence: [evidence(lower, &reads), evidence(lower, &writes)].concat(),
        });
    }
    let stealth = found(lower, STEALTH);
    if let Some((web, runs)) = both(WEB, RUNS) {
        out.push(Hit {
            id: ids::DOWNLOAD,
            level: Level::Fail,
            note: format!(
                "downloads ({}) and runs ({}) a program",
                listing(web.iter().copied()),
                listing(runs.iter().copied())
            ),
            evidence: [evidence(lower, &web), evidence(lower, &runs)].concat(),
        });
    } else if !stealth.is_empty() {
        out.push(Hit {
            id: ids::DOWNLOAD,
            level: Level::Fail,
            note: format!("hides what it runs ({})", listing(stealth.iter().copied())),
            evidence: evidence(lower, &stealth),
        });
    }
    let directives = found(lower, DIRECTIVES);
    let commandish: Vec<&str> = SHELLISH.iter().chain(WEB).chain(RUNS).copied().collect();
    if !directives.is_empty() {
        out.push(Hit {
            id: ids::INJECTION,
            level: Level::Fail,
            note: format!("injects a directive ({})", listing(directives.iter().copied())),
            evidence: evidence(lower, &directives),
        });
    } else if let Some((coercion, command)) = near(lower, COERCION, &commandish, scopes) {
        out.push(Hit {
            id: ids::INJECTION,
            level: Level::Fail,
            note: format!(
                "tells the model to keep quiet or act ({}) beside a command ({})",
                listing(coercion.iter().copied()),
                listing(command.iter().copied())
            ),
            evidence: [evidence(lower, &coercion), evidence(lower, &command)].concat(),
        });
    }
    let overridden = overrides(lower, scopes);
    if !overridden.is_empty() {
        let shown: Vec<String> = overridden.iter().map(|(_, w)| short_str(w)).collect();
        out.push(Hit {
            id: ids::OVERRIDE,
            level: Level::Warn,
            note: format!(
                "tells the model to set aside what it was told ({})",
                listing(shown.iter().map(String::as_str))
            ),
            evidence: overridden.iter().map(|&(at, _)| at).collect(),
        });
    }
    let hosts: Vec<(usize, String)> = url_hosts(lower).into_iter().filter(|(_, h)| !host_allowed(h)).collect();
    let tampered = tampers(lower, scopes);
    if !tampered.is_empty() {
        // Beside a command, a download or a URL, what is added is a payload.
        let mut beside = word_places(lower, &commandish);
        beside.extend(url_hosts(lower).into_iter().map(|(at, _)| (at, "a URL")));
        beside.sort_unstable();
        let payload: Vec<&str> = tampered
            .iter()
            .flat_map(|&(at, _)| {
                let lo = beside.partition_point(|&(p, _)| p + NEAR < at);
                beside[lo..]
                    .iter()
                    .take_while(move |&&(p, _)| p <= at + NEAR)
                    .filter(move |&&(p, _)| same_scope(scopes, at, p))
            })
            .map(|&(_, w)| w)
            .collect();
        let shown: Vec<String> = tampered.iter().map(|(_, w)| short_str(w)).collect();
        let what = listing(shown.iter().map(String::as_str));
        out.push(if payload.is_empty() {
            Hit {
                id: ids::TAMPER,
                level: Level::Warn,
                note: format!("tells the model to add something to its answers or code ({what})"),
                evidence: tampered.iter().map(|&(at, _)| at).collect(),
            }
        } else {
            Hit {
                id: ids::TAMPER,
                level: Level::Fail,
                note: format!(
                    "tells the model to add something to its answers or code ({what}) beside a command or URL ({})",
                    listing(payload)
                ),
                evidence: tampered.iter().map(|&(at, _)| at).collect(),
            }
        });
    }
    if !hosts.is_empty() {
        let mut shown: Vec<&str> = Vec::new();
        for (_, h) in &hosts {
            if !shown.contains(&h.as_str()) && shown.len() < 3 {
                shown.push(h);
            }
        }
        out.push(Hit {
            id: ids::URL,
            level: Level::Warn,
            note: format!("names a URL on {}", shown.join(", ")),
            evidence: hosts.iter().map(|&(at, _)| at).collect(),
        });
    }
    let shell = found(lower, SHELL);
    let failed = out.iter().any(|h| h.level == Level::Fail);
    if !shell.is_empty() && !failed {
        out.push(Hit {
            id: ids::SHELL,
            level: Level::Warn,
            note: format!("shell vocabulary ({})", listing(shell.iter().copied())),
            evidence: evidence(lower, &shell),
        });
    }
    out
}

/// What the rules find in one template. `source` names where it came
/// from (`tokenizer.chat_template`, `tokenizer_config.json`).
///
/// The dropper and download rules match their two kinds of words anywhere
/// in the template: padding between the halves doesn't hide them. Coercion
/// beside a command wants the two within [`NEAR`] bytes and in the same
/// text run or Jinja block, since a stock tool-calling line ("do not tell
/// the user about function calls") and a persona naming a shell can sit
/// far apart in a long template; then the shell word alone still warns.
/// Comments (`{# #}`) never reach the model and are not read, except for
/// hidden characters.
pub fn check(source: &str, text: &str) -> Vec<Issue> {
    let (segments, problem) = scan(text);
    // Byte ranges of the segments, and the text with comments blanked. A
    // comment renders to nothing, so text runs with only comments between
    // them are one run (`Never mention {##} powershell`); a statement or an
    // expression still ends a run.
    let base = text.as_ptr() as usize;
    let mut scopes: Vec<(usize, usize)> = Vec::new();
    let mut lower = text.to_ascii_lowercase();
    let mut in_text = false;
    for seg in &segments {
        let (Segment::Text(x) | Segment::Stmt(x) | Segment::Expr(x) | Segment::Comment(x)) = seg;
        let start = x.as_ptr() as usize - base;
        match seg {
            Segment::Comment(_) => lower.replace_range(start..start + x.len(), &" ".repeat(x.len())),
            Segment::Text(_) if in_text => {
                if let Some(last) = scopes.last_mut() {
                    last.1 = start + x.len();
                }
            }
            _ => {
                in_text = matches!(seg, Segment::Text(_));
                scopes.push((start, start + x.len()));
            }
        }
    }
    let mut hits = text_rules(&lower, &scopes);

    if let Some(why) = problem {
        hits.push(Hit {
            id: ids::UNREADABLE,
            level: Level::Warn,
            note: format!("doesn't tokenize as a Jinja template ({why})"),
            evidence: Vec::new(),
        });
    }
    let mut trigger: Option<String> = None;
    let mut rebuilt: Vec<usize> = Vec::new();
    let mut ssti: Vec<&str> = Vec::new();
    let mut ssti_at: Vec<usize> = Vec::new();
    let mut frames: Vec<Frame> = Vec::new();
    for seg in &segments {
        let code = match seg {
            Segment::Stmt(s) | Segment::Expr(s) => *s,
            _ => continue,
        };
        let at = code.as_ptr() as usize - base;
        let lc = code.to_ascii_lowercase();
        for w in found(&lc, SSTI) {
            if !ssti.contains(&w) {
                ssti.push(w);
            }
            ssti_at.extend(places(&lc, w, MAX_PLACES).into_iter().map(|p| at + p));
        }
        let no_system = frames.iter().any(|f| f.no_system);
        if let Segment::Stmt(s) = seg {
            let word = head(s);
            let cond = s.get(word.len()..).unwrap_or("");
            match word {
                "if" => {
                    let t = tests_for_system(cond);
                    frames.push(Frame { is_if: true, after_present: t == Some(true), no_system: t == Some(false) });
                }
                "elif" => {
                    if let Some(f) = frames.last_mut().filter(|f| f.is_if) {
                        let t = tests_for_system(cond);
                        f.no_system = f.after_present || t == Some(false);
                        f.after_present |= t == Some(true);
                    }
                }
                "else" => {
                    if let Some(f) = frames.last_mut().filter(|f| f.is_if) {
                        f.no_system = f.after_present;
                    }
                }
                w if BLOCKS.contains(&w) || (w == "set" && !s.contains('=')) => {
                    frames.push(Frame { is_if: false, after_present: false, no_system: false });
                }
                w if w.starts_with("end") => {
                    frames.pop();
                }
                _ => {}
            }
            if (word == "if" || word == "elif")
                && trigger.is_none()
                && let Some(lit) = content_tests(s).into_iter().find(|l| !normal_literal(l))
            {
                trigger = Some(short(lit));
            }
            if word == "set"
                && let Some((_, rhs)) = s.split_once('=')
                && has(&rhs.to_ascii_lowercase(), "messages")
                && adds_message(rhs)
                && !(no_system && !commands(&lc))
            {
                rebuilt.push(at);
            }
        }
        if (lc.contains("messages.insert(") || lc.contains("messages.append("))
            && adds_message(code)
            && !(no_system && !commands(&lc))
        {
            rebuilt.push(at);
        }
    }
    if let Some(lit) = trigger {
        hits.push(Hit {
            id: ids::TRIGGER,
            level: Level::Warn,
            note: format!("an `if` tests a message's content against {lit}: a trigger phrase?"),
            evidence: Vec::new(),
        });
    }
    if !rebuilt.is_empty() {
        hits.push(Hit {
            id: ids::SYSTEM,
            level: Level::Warn,
            note: "adds a system or user message with its own instruction text to the conversation".into(),
            evidence: rebuilt,
        });
    }
    if !ssti.is_empty() {
        hits.push(Hit {
            id: ids::SSTI,
            level: Level::Warn,
            note: format!("template sandbox escape vocabulary ({})", listing(ssti.iter().copied())),
            evidence: ssti_at,
        });
    }
    let mut out: Vec<Issue> =
        hits.into_iter().map(|h| Issue::new(h.id, h.level, format!("{source}: {}", h.note))).collect();
    for h in crate::checks::hidden::scan_text("chat_template.jinja", text) {
        if matches!(h.id, "HIDDEN-TAGS" | "HIDDEN-ZERO-WIDTH") || (h.id == "HIDDEN-BIDI" && h.hard) {
            let level = if h.hard { Level::Fail } else { Level::Warn };
            out.push(Issue::new(ids::HIDDEN, level, format!("{source}: {} ({})", h.note, h.id)));
        }
    }
    super::sorted(out)
}

#[cfg(test)]
#[path = "template_tests.rs"]
mod tests;
