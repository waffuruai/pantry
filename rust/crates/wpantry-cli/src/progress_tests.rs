use super::*;

#[test]
fn answers() {
    assert_eq!(answer("\n", false), Some(false));
    assert_eq!(answer("\n", true), Some(true));
    assert_eq!(answer(" Y\n", false), Some(true));
    assert_eq!(answer("yes", false), Some(true));
    assert_eq!(answer("NO\n", true), Some(false));
    assert_eq!(answer("maybe", true), None);
}

#[test]
fn fits_long_paths_by_their_end() {
    assert_eq!(fit("Reading ~/a/b/Cargo.lock", 100), "Reading ~/a/b/Cargo.lock");
    assert_eq!(fit("Reading ~/a/b/Cargo.lock", 12), "…/Cargo.lock");
    assert_eq!(fit("Reading ~/a/b/Cargo.lock", 12).chars().count(), 12);
}

#[test]
fn disabled_progress_has_no_thread() {
    let p = Progress::new(false);
    p.set("Reading x");
    assert!(p.ticker.lock().unwrap().is_none());
    p.finish();
}

#[test]
fn enabled_progress_stops_its_thread() {
    let p = Progress::new(true);
    p.set("Reading x");
    p.finish();
    assert!(p.ticker.lock().unwrap().is_none());
}

/// Off a terminal (CI) `start` shows nothing; on one it draws and stops.
#[test]
fn start_decides_by_the_terminal_and_always_finishes() {
    let p = Progress::start();
    p.set("Reading x");
    p.finish();
    assert!(p.ticker.lock().unwrap().is_none());
}

#[test]
fn set_keeps_the_message_and_ignores_a_repeat() {
    let p = Progress::new(true);
    p.set("Reading x");
    p.set("Reading x");
    p.set("Reading y");
    assert_eq!(p.state.as_ref().unwrap().lock().unwrap().message, "Reading y");
    p.finish();
}

#[test]
fn printing_while_the_line_is_up_clears_it_first() {
    let p = Progress::new(true);
    // Stop the ticker first: a redraw between a print and its assertion
    // would put the line back.
    p.finish();
    {
        let mut st = p.state.as_ref().unwrap().lock().unwrap();
        st.drawn = 12;
        draw(&mut st, Duration::from_secs(3));
        assert!(st.drawn > 0);
    }
    p.println("a report line");
    assert_eq!(p.state.as_ref().unwrap().lock().unwrap().drawn, 0);
    p.eprintln("a note");
    p.state.as_ref().unwrap().lock().unwrap().drawn = 7;
    p.eprintln("another note");
    assert_eq!(p.state.as_ref().unwrap().lock().unwrap().drawn, 0);
    p.finish();
    let quiet = Progress::new(false);
    quiet.println("plain");
    quiet.eprintln("plain note");
}

fn asked(p: &Progress, default: bool, typed: &str) -> (Option<bool>, String) {
    let mut out = Vec::new();
    let got = p.ask_on("Run it now?", default, &mut typed.as_bytes(), &mut out);
    (got, String::from_utf8(out).unwrap())
}

#[test]
fn ask_reads_an_answer_or_takes_the_default() {
    let p = Progress::new(false);
    let (got, out) = asked(&p, true, "\n");
    assert_eq!(got, Some(true));
    assert!(out.contains("? Run it now? [Y/n] "), "{out:?}");
    assert_eq!(asked(&p, false, "y\n").0, Some(true));
    let (got, out) = asked(&p, false, "what\nno\n");
    assert_eq!(got, Some(false));
    assert!(out.contains("[y/N]") && out.contains("Please answer y or n."), "{out:?}");
}

#[test]
fn ask_gives_up_at_end_of_input_or_after_three_tries() {
    let p = Progress::new(true);
    let (got, out) = asked(&p, true, "");
    assert_eq!(got, None);
    assert!(out.ends_with("[Y/n] \n"), "{out:?}");
    let (got, out) = asked(&p, true, "a\nb\nc\nd\n");
    assert_eq!(got, None);
    assert_eq!(out.matches("Please answer").count(), 3);
    p.finish();
}
