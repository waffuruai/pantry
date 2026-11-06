//! Words to [`Matches`]: options wherever they come, a word that names a
//! subcommand descends into it, the rest fill the arguments in order.

use crate::{Command, Exit, Opt, Takes, help};
use std::str::FromStr;

/// What was given: the commands named, each option's values in the order
/// given, each argument's words.
#[derive(Clone, Debug, PartialEq)]
pub struct Matches {
    path: Vec<String>,
    usage: String,
    /// (option name, value; None for a flag or a left-out optional value).
    given: Vec<(String, Option<String>)>,
    /// (option name, default value; as help shows it, for errors).
    opts: Vec<(String, Option<String>, String)>,
    args: Vec<(String, Vec<String>)>,
}

impl Matches {
    /// The command run: the last one named (`gen` for `rules gen`), or the
    /// program's name when none was.
    pub fn command(&self) -> &str {
        self.path.last().map(String::as_str).unwrap_or_default()
    }

    /// Every command named after the program's: `["rules", "gen"]`.
    pub fn path(&self) -> Vec<&str> {
        self.path.iter().skip(1).map(String::as_str).collect()
    }

    /// Whether the option was given at all.
    pub fn flag(&self, name: &str) -> bool {
        self.given.iter().any(|(n, _)| n == name)
    }

    /// The option's value: the last given, else its default.
    pub fn value(&self, name: &str) -> Option<&str> {
        self.given
            .iter()
            .rev()
            .find(|(n, v)| n == name && v.is_some())
            .and_then(|(_, v)| v.as_deref())
            .or_else(|| self.opts.iter().find(|(n, _, _)| n == name).and_then(|(_, d, _)| d.as_deref()))
    }

    /// Every value the option was given, in order.
    pub fn values(&self, name: &str) -> Vec<&str> {
        self.given.iter().filter(|(n, _)| n == name).filter_map(|(_, v)| v.as_deref()).collect()
    }

    /// The option's value parsed as a `T`; an unparsable one is a usage
    /// error naming the option.
    pub fn get<T: FromStr>(&self, name: &str) -> Result<Option<T>, Exit> {
        match self.value(name) {
            None => Ok(None),
            Some(v) => v.parse::<T>().map(Some).map_err(|_| {
                let shown = self.opts.iter().find(|(n, _, _)| n == name).map_or(name, |(_, _, s)| s.as_str());
                self.error(&format!("option '{shown}' argument '{v}' is invalid"))
            }),
        }
    }

    /// The argument's word (its default when left out).
    pub fn arg(&self, name: &str) -> Option<&str> {
        self.args.iter().find(|(n, _)| n == name).and_then(|(_, v)| v.first()).map(String::as_str)
    }

    /// Every word of a variadic argument.
    pub fn args(&self, name: &str) -> Vec<&str> {
        self.args
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.iter().map(String::as_str).collect())
            .unwrap_or_default()
    }

    /// A usage error for the command run, for what only the program can
    /// check (`--undo` needs an id).
    pub fn error(&self, message: &str) -> Exit {
        Exit::Error(format!("{}\nerror: {message}\n", self.usage))
    }
}

/// The edit distance between two words (insertions, deletions,
/// substitutions and swaps of neighbours).
fn distance(a: &str, b: &str) -> usize {
    let (a, b): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    let mut d = vec![vec![0usize; b.len() + 1]; a.len() + 1];
    for (i, row) in d.iter_mut().enumerate() {
        row[0] = i;
    }
    for (j, cell) in d[0].iter_mut().enumerate() {
        *cell = j;
    }
    for i in 1..=a.len() {
        for j in 1..=b.len() {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            d[i][j] = (d[i - 1][j] + 1).min(d[i][j - 1] + 1).min(d[i - 1][j - 1] + cost);
            if i > 1 && j > 1 && a[i - 1] == b[j - 2] && a[i - 2] == b[j - 1] {
                d[i][j] = d[i][j].min(d[i - 2][j - 2] + 1);
            }
        }
    }
    d[a.len()][b.len()]
}

/// The candidates closest to `word`, when close enough to be a typo
/// (commander's rule: within an edit distance of 3 and 40% of the length).
fn similar<'a>(word: &str, candidates: impl Iterator<Item = &'a str>) -> Vec<&'a str> {
    let mut best: Vec<&str> = Vec::new();
    let mut best_d = usize::MAX;
    for c in candidates {
        let d = distance(word, c);
        let len = word.chars().count().max(c.chars().count());
        if d == 0 || d > 3 || (len - d) * 10 < len * 4 {
            continue;
        }
        if d < best_d {
            best_d = d;
            best = vec![c];
        } else if d == best_d && !best.contains(&c) {
            best.push(c);
        }
    }
    best.sort_unstable();
    best
}

fn did_you_mean(names: &[&str]) -> String {
    match names {
        [] => String::new(),
        [one] => format!("\n(Did you mean {one}?)"),
        many => format!("\n(Did you mean one of {}?)", many.join(", ")),
    }
}

/// The options in scope at the end of `chain`: its own, then its parents'.
fn in_scope<'a>(chain: &[&'a Command]) -> impl Iterator<Item = &'a Opt> {
    chain.iter().rev().flat_map(|c| c.opts.iter())
}

pub fn parse<S: AsRef<str>>(root: &Command, argv: &[S]) -> Result<Matches, Exit> {
    let argv: Vec<&str> = argv.iter().map(AsRef::as_ref).collect();
    let mut chain: Vec<&Command> = vec![root];
    let mut given: Vec<(String, Option<String>)> = Vec::new();
    let mut words: Vec<&str> = Vec::new();
    let mut only_words = false;
    let fail = |chain: &[&Command], msg: String| Exit::Error(format!("{}\nerror: {msg}\n", help::usage(chain)));
    if argv.is_empty() && !root.commands.is_empty() && root.args.is_empty() {
        return Err(Exit::Help(help::help(&chain)));
    }
    let mut i = 0;
    while i < argv.len() {
        let word = argv[i];
        i += 1;
        if only_words || word == "-" || !word.starts_with('-') {
            // A subcommand's name, before any argument of this command.
            let cmd = chain[chain.len() - 1];
            if !only_words && words.is_empty() && !cmd.commands.is_empty() {
                if let Some(sub) = cmd.find_command(word) {
                    chain.push(sub);
                    continue;
                }
                if word == "help" {
                    let path: Vec<&str> = argv[i..].iter().copied().filter(|w| !w.starts_with('-')).collect();
                    let mut target = chain.clone();
                    for name in path {
                        let last = target[target.len() - 1];
                        match last.find_command(name) {
                            Some(c) => target.push(c),
                            None => return Err(unknown_command(&target, name)),
                        }
                    }
                    return Err(Exit::Help(help::help(&target)));
                }
                if cmd.args.is_empty() {
                    return Err(unknown_command(&chain, word));
                }
            }
            words.push(word);
            continue;
        }
        if word == "--" {
            only_words = true;
            continue;
        }
        // An option: `--name`, `--name=value`, `-x`, `-xvalue`, `-xyz`.
        let (opt, inline) = if let Some(long) = word.strip_prefix("--") {
            let (name, inline) = match long.split_once('=') {
                Some((n, v)) => (n, Some(v.to_string())),
                None => (long, None),
            };
            if name == "help" {
                return Err(Exit::Help(help::help(&chain)));
            }
            if name == "version" && chain.len() == 1 && root.version.is_some() {
                return Err(Exit::Version(version(root)));
            }
            match in_scope(&chain).find(|o| o.long.as_deref() == Some(name)) {
                Some(o) => (o, inline),
                None => {
                    let mut names: Vec<String> =
                        in_scope(&chain).filter(|o| !o.hidden).filter_map(|o| o.long.clone()).collect();
                    names.push("help".into());
                    let close = similar(name, names.iter().map(String::as_str));
                    let close: Vec<String> = close.iter().map(|n| format!("--{n}")).collect();
                    let close: Vec<&str> = close.iter().map(String::as_str).collect();
                    return Err(fail(&chain, format!("unknown option '--{name}'{}", did_you_mean(&close))));
                }
            }
        } else {
            let mut chars = word[1..].chars();
            let c = chars.next().expect("a dash and more");
            let rest: String = chars.collect();
            if c == 'h' && in_scope(&chain).all(|o| o.short != Some('h')) {
                return Err(Exit::Help(help::help(&chain)));
            }
            if c == 'V' && chain.len() == 1 && root.version.is_some() {
                return Err(Exit::Version(version(root)));
            }
            let Some(o) = in_scope(&chain).find(|o| o.short == Some(c)) else {
                return Err(fail(&chain, format!("unknown option '-{c}'")));
            };
            match (&o.takes, rest.is_empty()) {
                (_, true) => (o, None),
                (Takes::Value { .. }, false) => (o, Some(rest)),
                // `-abc`: flags one after another.
                (Takes::Nothing, false) => {
                    let mut flags = vec![o];
                    for c in rest.chars() {
                        match in_scope(&chain).find(|o| o.short == Some(c)) {
                            Some(f) if f.takes == Takes::Nothing => flags.push(f),
                            _ => return Err(fail(&chain, format!("unknown option '-{c}' in '{word}'"))),
                        }
                    }
                    for f in flags {
                        record(&chain, &mut given, f, None)?;
                    }
                    continue;
                }
            }
        };
        let value = match (&opt.takes, inline) {
            (Takes::Nothing, Some(v)) => {
                return Err(fail(&chain, format!("option '{}' takes no value, got '{v}'", opt.shown())));
            }
            (Takes::Nothing, None) => None,
            (Takes::Value { .. }, Some(v)) => Some(v),
            // A required value is the next word whatever it is (`-o -`).
            (Takes::Value { required: true, .. }, None) if i < argv.len() => {
                i += 1;
                Some(argv[i - 1].to_string())
            }
            (Takes::Value { required: true, .. }, None) => {
                return Err(fail(&chain, format!("option '{}' argument missing", opt.shown())));
            }
            (Takes::Value { required: false, .. }, None) if i < argv.len() && !argv[i].starts_with('-') => {
                i += 1;
                Some(argv[i - 1].to_string())
            }
            (Takes::Value { required: false, .. }, None) => None,
        };
        record(&chain, &mut given, opt, value)?;
        // `<value...>`: the words after it, up to the next option.
        if let Takes::Value { many: true, .. } = opt.takes {
            while i < argv.len() && !argv[i].starts_with('-') {
                record(&chain, &mut given, opt, Some(argv[i].to_string()))?;
                i += 1;
            }
        }
    }
    let cmd = chain[chain.len() - 1];
    if cmd.needs_command {
        let names: Vec<&str> = cmd.commands.iter().filter(|c| !c.hidden).map(|c| c.name.as_str()).collect();
        return Err(fail(&chain, format!("missing command: one of {}", names.join(", "))));
    }
    let args = assign(&chain, &words)?;
    let opts = in_scope(&chain).map(|o| (o.name(), o.default.clone(), o.shown())).collect();
    Ok(Matches { path: chain.iter().map(|c| c.name.clone()).collect(), usage: help::usage(&chain), given, opts, args })
}

fn version(root: &Command) -> String {
    format!("{} {}\n", root.name, root.version.as_deref().unwrap_or_default())
}

fn unknown_command(chain: &[&Command], word: &str) -> Exit {
    let cmd = chain[chain.len() - 1];
    let names = cmd.commands.iter().filter(|c| !c.hidden).flat_map(|c| std::iter::once(&c.name).chain(&c.aliases));
    let close = similar(word, names.map(String::as_str));
    Exit::Error(format!("{}\nerror: unknown command '{word}'{}\n", help::usage(chain), did_you_mean(&close)))
}

/// Note an option given, refusing a value outside its choices and an
/// option given with one it conflicts with.
fn record(
    chain: &[&Command],
    given: &mut Vec<(String, Option<String>)>,
    opt: &Opt,
    value: Option<String>,
) -> Result<(), Exit> {
    let fail = |msg: String| Exit::Error(format!("{}\nerror: {msg}\n", help::usage(chain)));
    if let Some(v) = &value
        && !opt.choices.is_empty()
        && !opt.choices.contains(v)
    {
        return Err(fail(format!(
            "option '{}' argument '{v}' is invalid. Allowed choices are {}.",
            opt.shown(),
            opt.choices.join(", ")
        )));
    }
    let name = opt.name();
    for (other, _) in given.iter() {
        let clash =
            opt.conflicts.contains(other) || in_scope(chain).any(|o| o.name() == *other && o.conflicts.contains(&name));
        if clash && *other != name {
            let shown = in_scope(chain).find(|o| o.name() == *other).map(Opt::shown).unwrap_or_default();
            return Err(fail(format!("option '{}' cannot be used with option '{shown}'", opt.shown())));
        }
    }
    given.push((name, value));
    Ok(())
}

/// The words to the command's arguments, in order; the last variadic one
/// takes the rest.
fn assign(chain: &[&Command], words: &[&str]) -> Result<Vec<(String, Vec<String>)>, Exit> {
    let cmd = chain[chain.len() - 1];
    let fail = |msg: String| Exit::Error(format!("{}\nerror: {msg}\n", help::usage(chain)));
    let mut out = Vec::new();
    let mut rest = words;
    for a in &cmd.args {
        let take = if a.many { rest.len() } else { rest.len().min(1) };
        let (mine, after) = rest.split_at(take);
        rest = after;
        if mine.is_empty() && a.required {
            return Err(fail(format!("missing required argument '{}'", a.name)));
        }
        for w in mine {
            if !a.choices.is_empty() && !a.choices.iter().any(|c| c == w) {
                return Err(fail(format!(
                    "argument '{w}' is invalid for '{}'. Allowed choices are {}.",
                    a.name,
                    a.choices.join(", ")
                )));
            }
        }
        let mut values: Vec<String> = mine.iter().map(|w| w.to_string()).collect();
        if values.is_empty()
            && let Some(d) = &a.default
        {
            values.push(d.clone());
        }
        out.push((a.name.clone(), values));
    }
    if !rest.is_empty() {
        let expected = cmd.args.len();
        let plural = if expected == 1 { "" } else { "s" };
        return Err(fail(format!(
            "too many arguments for '{}'. Expected {expected} argument{plural} but got {}: {}",
            cmd.name,
            words.len(),
            rest.join(" ")
        )));
    }
    Ok(out)
}

#[cfg(test)]
#[path = "parse_tests.rs"]
mod tests;
