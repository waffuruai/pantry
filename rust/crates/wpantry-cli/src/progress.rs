//! The live progress line while a scan runs: a spinner, what the scan is
//! doing (the step, the directory or file it is reading) and the elapsed
//! time, redrawn in place on stderr. Only when stderr is a terminal (and
//! TERM isn't "dumb"), so pipes, CI logs and `--json` callers see nothing.
//! Coloured as [`Style::stderr`] allows (the spinner, the clock); plain with
//! `NO_COLOR`. Also asks the scan's yes/no questions ([`Progress::ask`]).

use crate::style::Style;
use std::io::{BufRead, IsTerminal, Write};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const FRAMES: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
const TICK: Duration = Duration::from_millis(80);

#[derive(Default)]
struct State {
    message: String,
    /// Characters on the line now, to blank before the next draw.
    drawn: usize,
    frame: usize,
    done: bool,
    style: Style,
}

pub struct Progress {
    state: Option<Arc<Mutex<State>>>,
    start: Instant,
    ticker: Mutex<Option<JoinHandle<()>>>,
}

fn width() -> usize {
    std::env::var("COLUMNS").ok().and_then(|c| c.parse::<usize>().ok()).filter(|w| *w > 20).unwrap_or(80)
}

/// `text` cut to `max` characters, keeping its end (where the file name is).
pub fn fit(text: &str, max: usize) -> String {
    let n = text.chars().count();
    if n <= max {
        return text.to_string();
    }
    let keep: String = text.chars().skip(n - (max - 1)).collect();
    format!("…{keep}")
}

fn draw(s: &mut State, elapsed: Duration) {
    let frame = FRAMES[s.frame % FRAMES.len()];
    let clock = format!(" · {}s", elapsed.as_secs());
    let room = width().saturating_sub(3 + clock.chars().count() + 1);
    let message = fit(&s.message, room);
    let len = format!("{frame} {message}{clock}").chars().count();
    let pad = s.drawn.saturating_sub(len);
    let line = format!("{} {message}{}", s.style.cyan(&frame.to_string()), s.style.dim(&clock));
    let mut err = std::io::stderr().lock();
    let _ = write!(err, "\r{line}{}", " ".repeat(pad));
    let _ = err.flush();
    s.drawn = len;
}

fn clear(s: &mut State) {
    if s.drawn > 0 {
        let mut err = std::io::stderr().lock();
        let _ = write!(err, "\r{}\r", " ".repeat(s.drawn));
        let _ = err.flush();
        s.drawn = 0;
    }
}

impl Progress {
    /// A progress line when stderr is a terminal; otherwise one that shows
    /// nothing.
    pub fn start() -> Progress {
        let tty = std::io::stderr().is_terminal() && std::env::var("TERM").map_or(true, |t| t != "dumb");
        Progress::new(tty)
    }

    pub fn new(enabled: bool) -> Progress {
        let start = Instant::now();
        if !enabled {
            return Progress { state: None, start, ticker: Mutex::new(None) };
        }
        let state =
            Arc::new(Mutex::new(State { message: "Starting".into(), style: Style::stderr(), ..Default::default() }));
        let s = state.clone();
        let ticker = std::thread::spawn(move || {
            loop {
                {
                    let mut st = s.lock().expect("progress");
                    if st.done {
                        clear(&mut st);
                        return;
                    }
                    st.frame += 1;
                    draw(&mut st, start.elapsed());
                }
                std::thread::sleep(TICK);
            }
        });
        Progress { state: Some(state), start, ticker: Mutex::new(Some(ticker)) }
    }

    /// The scan's current step; drawn on the next tick.
    pub fn set(&self, message: &str) {
        if let Some(s) = &self.state {
            let mut st = s.lock().expect("progress");
            if st.message != message {
                st.message.clear();
                st.message.push_str(message);
            }
        }
    }

    /// Print a line of the report while the progress line is up: blank the
    /// line, print, and let the next tick redraw below it.
    pub fn println(&self, line: &str) {
        match &self.state {
            Some(s) => {
                let mut st = s.lock().expect("progress");
                clear(&mut st);
                println!("{line}");
                let _ = std::io::stdout().flush();
            }
            None => println!("{line}"),
        }
    }

    /// Ask a yes/no question on the terminal, the progress line paused:
    /// `? Question [y/N]` on stderr, Enter takes the default, anything but
    /// y/yes/n/no asks again. None when stdin isn't a terminal or closes
    /// (nobody to answer), so the caller leaves the decision for later.
    pub fn ask(&self, question: &str, default: bool) -> Option<bool> {
        if !std::io::stdin().is_terminal() {
            return None;
        }
        let mut guard = self.state.as_ref().map(|s| s.lock().expect("progress"));
        if let Some(st) = guard.as_mut() {
            clear(st);
        }
        let style = Style::stderr();
        let hint = if default { "[Y/n]" } else { "[y/N]" };
        let stdin = std::io::stdin();
        for _ in 0..3 {
            eprint!("{} {} {} ", style.cyan("?"), style.bold(question), style.dim(hint));
            let _ = std::io::stderr().flush();
            let mut line = String::new();
            if stdin.lock().read_line(&mut line).ok()? == 0 {
                eprintln!();
                return None;
            }
            if let Some(answer) = answer(&line, default) {
                return Some(answer);
            }
            eprintln!("  {}", style.yellow("Please answer y or n."));
        }
        None
    }

    /// A one-line note on stderr while the progress line is up.
    pub fn eprintln(&self, line: &str) {
        if let Some(s) = &self.state {
            clear(&mut s.lock().expect("progress"));
        }
        eprintln!("{line}");
    }

    /// Stop and blank the progress line; no thread outlives this (P4).
    pub fn finish(&self) -> Duration {
        if let Some(s) = &self.state {
            s.lock().expect("progress").done = true;
        }
        if let Some(t) = self.ticker.lock().expect("progress").take() {
            let _ = t.join();
        }
        self.start.elapsed()
    }
}

impl Drop for Progress {
    fn drop(&mut self) {
        self.finish();
    }
}

/// A typed answer: y/yes or n/no in any case, Enter for the default; None
/// for anything else.
fn answer(line: &str, default: bool) -> Option<bool> {
    match line.trim().to_lowercase().as_str() {
        "" => Some(default),
        "y" | "yes" => Some(true),
        "n" | "no" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
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
}
