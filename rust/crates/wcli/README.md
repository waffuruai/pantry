# wcli

Command-line parsing for Waffuru's Rust tools, after [commander.js](https://github.com/tj/commander.js). You declare each command once, with options and arguments written the way its help shows them. From that, wcli generates the parser, the usage line, the help, and the errors. It has no dependencies and no macros. It lives in pantry while [`wpantry-cli`](../wpantry-cli/src/args.rs) tries it out, and moves to its own repo when a second tool needs it.

```rust
use wcli::{Arg, Command, Opt};

let program = Command::new("tool")
    .version("1.0.0")
    .description("Does things.")
    .command(
        Command::new("report")
            .description("Show the latest report.")
            .arg(Arg::new("[part]", "what it covers").choices(&["findings", "summary"]).default("findings"))
            .option("--json", "as JSON")
            .option("-o, --out <file>", "write it there")
            .opt(Opt::new("--since <days>", "how far back").default("14")),
    )
    .command(
        Command::new("schedule")
            .subcommand_required()
            .command(Command::new("install").opt(Opt::new("--every <period>", "how often").choices(&["day", "week"]))),
    );

let argv: Vec<String> = std::env::args().skip(1).collect();
let m = program.parse(&argv).unwrap_or_else(|exit| exit.exit()); // help, version or a usage error
match m.path().as_slice() {
    ["report"] => {
        let since: u32 = m.get("since").unwrap_or_else(|e| e.exit()).unwrap_or(14);
        println!("{:?} {} {since}", m.arg("part"), m.flag("json"));
    }
    ["schedule", "install"] => println!("{:?}", m.value("every")),
    _ => unreachable!(),
}
```

## Specs

| Spec | Means |
|---|---|
| `--json` | A flag: `m.flag("json")` |
| `-o, --out <file>` | Takes a value: `-o x`, `-ox`, `--out x`, `--out=x`. The next word is always the value, even `-` |
| `--licenses [file]` | The value may be left out: `m.flag("licenses")` says it was given, and `m.value("licenses")` gives the value if there is one |
| `--tag <name...>` | Takes the words after it until the next option. Every option also collects a value each time it is repeated: `m.values("tag")` |
| `<query>`, `[part]`, `<sample...>` | Arguments: required, optional, and the rest of the words. Read them with `m.arg("query")` and `m.args("sample")` |

`Opt` adds `.choices(&[..])`, `.default(..)`, `.conflicts(&[..])` (options that can't be given together) and `.hide()`. `Arg` adds `.choices` and `.default`. `Command` adds:

- `.alias(..)`
- `.summary(..)`, the command's line in its parent's list; without it, the first sentence of the description
- `.after_help(..)`
- `.subcommand_required()`
- `.hide()`
- `.opts(..)`, a set of options several commands share

## What you get

- `-h` and `--help` on every command.
- `help [command...]` on every command with subcommands.
- `-V` and `--version` on the root when it has a version.
- With no words at all, the root's help.
- Errors in one shape: the usage line, then `error: …`, then `(Did you mean --json?)` when a name is close. They come back as `Exit::Error`, exit code 2. Help and the version come back as `Exit::Help` and `Exit::Version`, exit code 0. `exit.exit()` prints each where it belongs and ends the process.
- `m.get::<T>(name)` parses a value, and reports an option's bad value as a usage error.
- `m.error(msg)` makes a usage error for checks only the program can do.
- No abbreviations. An option must be spelled out in full; a typo gets a suggestion instead.
- Help that wraps to 100 columns, so it reads the same everywhere it is copied.
