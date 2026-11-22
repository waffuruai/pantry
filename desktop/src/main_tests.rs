use super::*;

fn args(list: &[&str]) -> Vec<OsString> {
    list.iter().map(OsString::from).collect()
}

#[test]
fn the_scheduled_run_flag_parses_alone_and_rejects_automation() {
    assert_eq!(
        parse(args(&["--scheduled-run"])),
        Ok(Launch::ScheduledRun { scanner: None })
    );
    assert!(parse(args(&["--scheduled-run", "--automation"])).is_err());
    assert!(parse(args(&["--automation", "--scheduled-run"])).is_err());
    assert_eq!(
        parse(args(&[])),
        Ok(Launch::App {
            scanner: None,
            automate: false
        })
    );
    assert_eq!(
        parse(args(&["--automation"])),
        Ok(Launch::App {
            scanner: None,
            automate: true
        })
    );
    assert_eq!(parse(args(&["--help"])), Ok(Launch::Help));
    assert_eq!(parse(args(&["--version"])), Ok(Launch::Version));
    assert!(parse(args(&["--scheduled"])).is_err());
    assert!(parse(args(&["--scanner"])).is_err());
}

#[test]
fn the_scheduled_run_flag_takes_a_scanner() {
    let here = std::env::current_exe().unwrap();
    let Ok(Launch::ScheduledRun {
        scanner: Some(path),
    }) = parse(vec![
        OsString::from("--scheduled-run"),
        OsString::from("--scanner"),
        here.clone().into_os_string(),
    ])
    else {
        panic!("expected a scheduled run with a scanner");
    };
    assert_eq!(path, here.canonicalize().unwrap());
}

#[test]
fn help_names_the_scheduled_run() {
    assert!(USAGE.contains("--scheduled-run"));
    assert!(USAGE.contains("--automation"));
}
