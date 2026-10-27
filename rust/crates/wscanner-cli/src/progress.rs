//! The live progress line while a scan runs: a spinner, what the scan is
//! doing (the step, the directory or file it is reading) and the elapsed
//! time, redrawn in place on stderr. Only when stderr is a terminal (and
//! TERM isn't "dumb"), so pipes, CI logs and `--json` callers see nothing.
//! Plain text and carriage returns only: no ANSI sequences (NO_COLOR holds).

use std::io::{IsTerminal, Write};
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
    let line = format!("{frame} {}{clock}", fit(&s.message, room));
    let len = line.chars().count();
    let pad = s.drawn.saturating_sub(len);
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
        let state = Arc::new(Mutex::new(State { message: "Starting".into(), ..Default::default() }));
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

    /// Ask a yes/no question on the terminal, the progress line paused; None
    /// when stdin isn't a terminal (nobody to answer).
    pub fn ask(&self, question: &str) -> Option<bool> {
        if !std::io::stdin().is_terminal() {
            return None;
        }
        let guard = self.state.as_ref().map(|s| s.lock().expect("progress"));
        let mut guard = guard;
        if let Some(st) = guard.as_mut() {
            clear(st);
        }
        print!("{question}");
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).ok()?;
        let reply = line.trim().to_lowercase();
        Some(reply == "y" || reply == "yes")
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

#[cfg(test)]
mod tests {
    use super::*;

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
