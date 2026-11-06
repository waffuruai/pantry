use super::*;
use crate::{Arg, Opt};

fn program() -> Command {
    Command::new("tool")
        .version("1.2.3")
        .description("does things. More about them here.")
        .command(
            Command::new("report")
                .description("show the latest report. It never scans.")
                .arg(Arg::new("[part]", "what it covers").choices(&["findings", "summary"]).default("findings"))
                .option("-o, --out <file>", "write it there")
                .opt(Opt::new("--since <days>", "how far back").default("14"))
                .opt(Opt::new("--secret", "hidden").hide())
                .after_help("Exit codes: 0 fine."),
        )
        .command(
            Command::new("schedule").summary("run on a schedule").subcommand_required().command(Command::new("run")),
        )
        .command(Command::new("internal").hide())
}

#[test]
fn the_help_lists_arguments_options_and_commands() {
    let root = program();
    let text = root.help_for(&[]).unwrap();
    assert!(text.starts_with("Usage: tool [options] [command]\n\ndoes things. More about them here.\n"), "{text}");
    assert!(text.contains("  -V, --version  print the version\n"), "{text}");
    assert!(text.contains("  report [options] [part]  show the latest report\n"), "{text}");
    assert!(text.contains("  schedule <command>       run on a schedule\n"), "{text}");
    assert!(text.contains("  help [command]           Print a command's help\n"), "{text}");
    assert!(!text.contains("internal"));
    let text = root.help_for(&["report"]).unwrap();
    assert!(text.starts_with("Usage: tool report [options] [part]\n"), "{text}");
    assert!(text.contains("  part  what it covers (choices: findings, summary; default: findings)\n"), "{text}");
    assert!(text.contains("  --since <days>    how far back (default: 14)\n"), "{text}");
    assert!(text.contains("  -h, --help        print this help\n"), "{text}");
    assert!(!text.contains("--secret") && !text.contains("--version"));
    assert!(text.ends_with("\nExit codes: 0 fine.\n"));
    assert_eq!(root.help_for(&["nope"]), None);
}

#[test]
fn long_text_wraps_under_its_column() {
    let long = "word ".repeat(40);
    let text = Command::new("t").option("--a", long.trim()).help_for(&[]).unwrap();
    for line in text.lines() {
        assert!(line.chars().count() <= WIDTH, "{line}");
    }
    assert!(text.contains("\n              word"), "{text}");
    let long_term = Command::new("t").option("--a-very-long-option-name <value>", "text").help_for(&[]).unwrap();
    assert!(long_term.contains("  --a-very-long-option-name <value>\n"), "{long_term}");
    assert_eq!(wrap("a\nb", 2, 80), "a\n  b");
}

#[test]
fn a_summary_is_the_descriptions_first_sentence() {
    assert_eq!(summary(&Command::new("x").description("does it. Then more.")), "does it");
    assert_eq!(summary(&Command::new("x").description("does it.")), "does it");
    assert_eq!(summary(&Command::new("x").description("one\ntwo")), "one");
    assert_eq!(summary(&Command::new("x").summary("own").description("does it.")), "own");
}

#[test]
fn aliases_show_where_they_are_declared() {
    let root = Command::new("t").command(Command::new("export").alias("ex"));
    assert!(root.help_for(&[]).unwrap().contains("  export|ex"));
    assert!(root.help_for(&["ex"]).unwrap().contains("Also: ex"));
}
