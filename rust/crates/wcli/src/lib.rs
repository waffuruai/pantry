//! Command-line parsing for Waffuru's tools, after [commander.js]: a tree of
//! commands, each declared with the flags and arguments it takes in the
//! words its help shows them in, and nothing else to write.
//!
//! ```
//! use wcli::{Command, Opt};
//!
//! let program = Command::new("tool")
//!     .version("1.0.0")
//!     .description("does things")
//!     .command(
//!         Command::new("report")
//!             .description("show the latest report")
//!             .argument("[part]", "what it covers")
//!             .option("-o, --out <file>", "write it there")
//!             .opt(Opt::new("--since <days>", "how far back").default("14")),
//!     );
//! let m = program.parse(&["report", "summary", "-o", "r.md"]).unwrap();
//! assert_eq!(m.command(), "report");
//! assert_eq!(m.arg("part"), Some("summary"));
//! assert_eq!(m.value("out"), Some("r.md"));
//! assert_eq!(m.get::<u32>("since").unwrap(), Some(14));
//! ```
//!
//! - **Options** are spelled as in help: `--json` (a flag), `-o, --out
//!   <file>` (takes a value), `--licenses [file]` (the value may be left
//!   out), `--path <dir...>` (one or more values; repeating it adds more).
//!   A value is given as the next word (`-o -` too) or after `=`; a short
//!   one also joined (`-ofile`). Options are looked up by their long name
//!   without the dashes (`m.flag("no-machine")`), or the short letter when
//!   there is no long one. There are no abbreviations: an option is spelled
//!   out or it is an error, with the closest names suggested.
//! - **Arguments**: `<name>` required, `[name]` optional, `<name...>` or
//!   `[name...]` the rest of the words.
//! - **Commands** nest: a word that names a subcommand descends into it,
//!   so `rules gen <sample...>` is a command of `rules`. Every command with
//!   subcommands gets `help [command...]`; every command gets `-h, --help`,
//!   and the root `-V, --version` when it has a version. An option of a
//!   command also works after its subcommands' names.
//! - **Errors** are [`Exit::Error`]: the usage line and one sentence,
//!   exit code 2. Help and version are [`Exit::Help`] and [`Exit::Version`],
//!   exit code 0.
//!
//! [commander.js]: https://github.com/tj/commander.js

mod help;
mod parse;

pub use help::WIDTH;
pub use parse::Matches;

/// What an option takes after its name.
#[derive(Clone, Debug, PartialEq)]
enum Takes {
    /// A flag: nothing.
    Nothing,
    /// `<name>`, or `[name]` when the value may be left out; `...` for many.
    Value { name: String, required: bool, many: bool },
}

/// An option: `-o, --out <file>` with its help, and what it accepts.
#[derive(Clone, Debug)]
pub struct Opt {
    short: Option<char>,
    long: Option<String>,
    takes: Takes,
    help: String,
    choices: Vec<String>,
    default: Option<String>,
    conflicts: Vec<String>,
    hidden: bool,
}

impl Opt {
    /// An option from its spec: `-s, --long`, `--long <value>`, `--long
    /// [value]`, `--long <value...>`, `-s`. A spec that is none of these is
    /// a bug in the program, not the user's mistake: it panics.
    pub fn new(spec: &str, help: &str) -> Opt {
        let mut short = None;
        let mut long = None;
        let mut takes = Takes::Nothing;
        for word in spec.split([',', ' ']).filter(|w| !w.is_empty()) {
            if let Some(l) = word.strip_prefix("--") {
                assert!(long.is_none() && !l.is_empty(), "wcli: bad option spec {spec:?}");
                long = Some(l.to_string());
            } else if let Some(s) = word.strip_prefix('-') {
                let mut chars = s.chars();
                let (Some(c), None) = (chars.next(), chars.next()) else { panic!("wcli: bad option spec {spec:?}") };
                short = Some(c);
            } else if let Some(inner) = word.strip_prefix('<').and_then(|w| w.strip_suffix('>')) {
                takes = value(inner, true);
            } else if let Some(inner) = word.strip_prefix('[').and_then(|w| w.strip_suffix(']')) {
                takes = value(inner, false);
            } else {
                panic!("wcli: bad option spec {spec:?}");
            }
        }
        assert!(short.is_some() || long.is_some(), "wcli: bad option spec {spec:?}");
        Opt {
            short,
            long,
            takes,
            help: help.to_string(),
            choices: Vec::new(),
            default: None,
            conflicts: Vec::new(),
            hidden: false,
        }
    }

    /// The values it accepts; any other is an error naming these.
    pub fn choices(mut self, choices: &[&str]) -> Opt {
        self.choices = choices.iter().map(|c| c.to_string()).collect();
        self
    }

    /// Its value when it isn't given.
    pub fn default(mut self, value: &str) -> Opt {
        self.default = Some(value.to_string());
        self
    }

    /// Options (by name) it can't be given with.
    pub fn conflicts(mut self, names: &[&str]) -> Opt {
        self.conflicts.extend(names.iter().map(|n| n.to_string()));
        self
    }

    /// Left out of the help; it still parses.
    pub fn hide(mut self) -> Opt {
        self.hidden = true;
        self
    }

    /// The name it is looked up by: the long one, else the letter.
    pub fn name(&self) -> String {
        self.long.clone().unwrap_or_else(|| self.short.map(String::from).unwrap_or_default())
    }

    /// As help shows it: `-o, --out <file>`.
    pub fn flags(&self) -> String {
        let mut out = String::new();
        if let Some(s) = self.short {
            out.push('-');
            out.push(s);
        }
        if let Some(l) = &self.long {
            if !out.is_empty() {
                out.push_str(", ");
            }
            out.push_str("--");
            out.push_str(l);
        }
        if let Takes::Value { name, required, many } = &self.takes {
            let dots = if *many { "..." } else { "" };
            if *required {
                out.push_str(&format!(" <{name}{dots}>"));
            } else {
                out.push_str(&format!(" [{name}{dots}]"));
            }
        }
        out
    }

    /// As an error names it: the spelling the user typed, with its value.
    fn shown(&self) -> String {
        self.flags()
    }
}

fn value(inner: &str, required: bool) -> Takes {
    let (name, many) = match inner.strip_suffix("...") {
        Some(n) => (n, true),
        None => (inner, false),
    };
    assert!(!name.is_empty(), "wcli: an option's value needs a name");
    Takes::Value { name: name.to_string(), required, many }
}

/// A positional argument: `<name>`, `[name]`, `<name...>`.
#[derive(Clone, Debug)]
pub struct Arg {
    name: String,
    required: bool,
    many: bool,
    help: String,
    choices: Vec<String>,
    default: Option<String>,
}

impl Arg {
    pub fn new(spec: &str, help: &str) -> Arg {
        let (inner, required) = if let Some(i) = spec.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
            (i, true)
        } else if let Some(i) = spec.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            (i, false)
        } else {
            panic!("wcli: bad argument spec {spec:?}: <name> or [name]")
        };
        let (name, many) = match inner.strip_suffix("...") {
            Some(n) => (n, true),
            None => (inner, false),
        };
        assert!(!name.is_empty(), "wcli: bad argument spec {spec:?}");
        Arg { name: name.to_string(), required, many, help: help.to_string(), choices: Vec::new(), default: None }
    }

    pub fn choices(mut self, choices: &[&str]) -> Arg {
        self.choices = choices.iter().map(|c| c.to_string()).collect();
        self
    }

    pub fn default(mut self, value: &str) -> Arg {
        self.default = Some(value.to_string());
        self
    }

    /// As a usage line shows it.
    fn spec(&self) -> String {
        let dots = if self.many { "..." } else { "" };
        if self.required { format!("<{}{dots}>", self.name) } else { format!("[{}{dots}]", self.name) }
    }
}

/// A command: its name, what it does, its options, arguments and
/// subcommands. The program is the root command.
#[derive(Clone, Debug, Default)]
pub struct Command {
    name: String,
    aliases: Vec<String>,
    version: Option<String>,
    description: String,
    summary: Option<String>,
    after: String,
    opts: Vec<Opt>,
    args: Vec<Arg>,
    commands: Vec<Command>,
    needs_command: bool,
    hidden: bool,
}

impl Command {
    pub fn new(name: &str) -> Command {
        Command { name: name.to_string(), ..Default::default() }
    }

    /// What it does: the help's paragraph, and (its first sentence, unless
    /// [`Command::summary`] says otherwise) its line in the parent's list.
    pub fn description(mut self, text: &str) -> Command {
        self.description = text.to_string();
        self
    }

    /// Its line in the parent's list of commands.
    pub fn summary(mut self, text: &str) -> Command {
        self.summary = Some(text.to_string());
        self
    }

    /// Another name it answers to.
    pub fn alias(mut self, name: &str) -> Command {
        self.aliases.push(name.to_string());
        self
    }

    /// The program's version: `-V, --version` prints `<name> <version>`.
    pub fn version(mut self, version: &str) -> Command {
        self.version = Some(version.to_string());
        self
    }

    /// Text after the options in the help (exit codes, examples).
    pub fn after_help(mut self, text: &str) -> Command {
        self.after = text.to_string();
        self
    }

    /// An option from its spec and help: [`Opt::new`].
    pub fn option(self, spec: &str, help: &str) -> Command {
        self.opt(Opt::new(spec, help))
    }

    /// An option built with choices, a default or conflicts.
    pub fn opt(mut self, opt: Opt) -> Command {
        let name = opt.name();
        assert!(
            !self.opts.iter().any(|o| o.name() == name || (o.short.is_some() && o.short == opt.short)),
            "wcli: option {} is declared twice on {}",
            opt.flags(),
            self.name
        );
        self.opts.push(opt);
        self
    }

    /// Options given together: one `opts` call per option, for a set
    /// several commands share.
    pub fn opts(self, opts: impl IntoIterator<Item = Opt>) -> Command {
        opts.into_iter().fold(self, Command::opt)
    }

    /// A positional argument from its spec and help: [`Arg::new`].
    pub fn argument(self, spec: &str, help: &str) -> Command {
        self.arg(Arg::new(spec, help))
    }

    pub fn arg(mut self, arg: Arg) -> Command {
        assert!(
            self.args.last().is_none_or(|a| !a.many),
            "wcli: nothing can follow the variadic argument of {}",
            self.name
        );
        assert!(
            !arg.required || self.args.iter().all(|a| a.required),
            "wcli: a required argument can't follow an optional one on {}",
            self.name
        );
        self.args.push(arg);
        self
    }

    /// A subcommand.
    pub fn command(mut self, command: Command) -> Command {
        self.commands.push(command);
        self
    }

    /// It does nothing alone: one of its subcommands must be named.
    pub fn subcommand_required(mut self) -> Command {
        self.needs_command = true;
        self
    }

    /// Left out of the parent's list; it still runs.
    pub fn hide(mut self) -> Command {
        self.hidden = true;
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Parse the words after the program's name.
    pub fn parse<S: AsRef<str>>(&self, argv: &[S]) -> Result<Matches, Exit> {
        parse::parse(self, argv)
    }

    /// The help of the command at `path` (names below this one), or None
    /// when there is no such command.
    pub fn help_for(&self, path: &[&str]) -> Option<String> {
        let mut chain = vec![self];
        for name in path {
            chain.push(chain.last()?.find_command(name)?);
        }
        Some(help::help(&chain))
    }

    fn find_command(&self, name: &str) -> Option<&Command> {
        self.commands.iter().find(|c| c.name == name || c.aliases.iter().any(|a| a == name))
    }
}

/// What parsing ends in when it doesn't end in [`Matches`].
#[derive(Clone, Debug, PartialEq)]
pub enum Exit {
    /// `-h`, `--help`, `help [command]`: the text for stdout, exit 0.
    Help(String),
    /// `-V`, `--version`: the line for stdout, exit 0.
    Version(String),
    /// A usage error: the usage line and the error for stderr, exit 2.
    Error(String),
}

impl Exit {
    /// The process's exit code: 0 for help and version, 2 for an error.
    pub fn code(&self) -> i32 {
        match self {
            Exit::Help(_) | Exit::Version(_) => 0,
            Exit::Error(_) => 2,
        }
    }

    pub fn text(&self) -> &str {
        match self {
            Exit::Help(t) | Exit::Version(t) | Exit::Error(t) => t,
        }
    }

    /// Print it where it belongs and end the process with its code.
    pub fn exit(&self) -> ! {
        if let Exit::Error(t) = self {
            eprint!("{t}");
        } else {
            print!("{}", self.text());
        }
        std::process::exit(self.code())
    }
}

#[cfg(test)]
#[path = "lib_tests.rs"]
mod tests;
