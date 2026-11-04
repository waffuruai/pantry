//! The resident clipboard guard, `wpantry clipboard --watch`. The scan's
//! self-test ([`crate::checks::machine::clipper`]) catches a clipper that rewrites a canary
//! while the scan runs; one that only wakes for a wallet with money in it,
//! or a browser extension that swaps the address as it is pasted, shows
//! itself while the person works. The guard polls the clipboard a few
//! times a second, remembers the last address it saw and when, and raises
//! an alert when an address of some chain turns into a different valid
//! address of the same chain within the window, with nothing but
//! addresses on the clipboard in between. The person then knows before
//! the funds are sent, which is the only moment it matters.
//!
//! The guard never writes the clipboard: putting the address back would
//! hide the clipper from the person and fight it for the clipboard. The
//! one false positive is a person copying two addresses of the same chain
//! inside the window; the alert says so, and the window is configurable.
//!
//! Change detection is a read and a compare: macOS has a pasteboard
//! change count, but reaching it needs `osascript` (far dearer than
//! `pbpaste`) or linking AppKit, which this crate doesn't; `pbpaste` four
//! times a second costs about five percent of one core, nearly all of it
//! in `pbpaste`. The quiet path makes no allocation beyond the read itself.

use crate::db::Cache;
use crate::error::Result;
use crate::history;
use crate::utils::addresses::{self, Chain};
use crate::utils::{os, process};
use serde_json::{Value, json};
use std::cell::Cell;
use std::ffi::OsStr;
use std::time::{Duration, Instant};

/// How often the clipboard is read.
pub const INTERVAL: Duration = Duration::from_millis(250);
/// The default window: two addresses of one chain inside it is a swap.
pub const WINDOW: Duration = Duration::from_secs(2);

/// A copied address that became another one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Alert {
    pub chain: Chain,
    pub from: String,
    pub to: String,
    /// How long after `from` appeared `to` did.
    pub after: Duration,
}

impl Alert {
    /// The one line a person reads.
    pub fn note(&self) -> String {
        format!(
            "clipboard swap: the {} address {} became {} after {:.1} s; something rewrote the clipboard. Don't paste it into a wallet. If you copied two addresses yourself, ignore this",
            self.chain.name(),
            self.from,
            self.to,
            self.after.as_secs_f64()
        )
    }

    /// The event as `--json` streams it and the cache's `events` table keeps it.
    pub fn to_json(&self, at: f64) -> Value {
        json!({
            "schema": crate::SCHEMA, "impl": crate::IMPL, "version": crate::VERSION,
            "event": "clipper", "at": at, "chain": self.chain.name(), "from": self.from, "to": self.to,
            "seconds": (self.after.as_secs_f64() * 100.0).round() / 100.0, "note": self.note(),
        })
    }
}

/// Record the swap in the cache's `events` table as a `clipper` event, so
/// `wpantry report --audit` lists it.
pub fn record(cache: &Cache, a: &Alert) -> Result<()> {
    let mut detail = a.to_json(os::now());
    if let Value::Object(o) = &mut detail {
        for k in ["schema", "impl", "version", "at"] {
            o.remove(k);
        }
    }
    history::event(cache, "clipper", &detail)
}

struct Last {
    chain: Chain,
    text: String,
    at: Instant,
}

/// What the guard remembers between reads.
pub struct Guard {
    window: Duration,
    last_text: String,
    last_address: Option<Last>,
}

/// The one address in `text`, when the text carries exactly one: the
/// address alone, or a line with one address in it.
fn the_address(text: &str) -> Option<(Chain, &str)> {
    let found = addresses::find(text, 2);
    match found.as_slice() {
        [one] => Some((one.chain, one.text)),
        _ => None,
    }
}

/// Whether two addresses of `chain` are the same one: EVM addresses have
/// no checksum in their case, and wallets write them both ways.
fn same(chain: Chain, a: &str, b: &str) -> bool {
    if chain == Chain::Evm { a.eq_ignore_ascii_case(b) } else { a == b }
}

impl Guard {
    pub fn new(window: Duration) -> Guard {
        Guard { window, last_text: String::new(), last_address: None }
    }

    /// One read of the clipboard at `now`. An unchanged clipboard costs a
    /// comparison; an empty read (no text on the clipboard, or the tool
    /// failed) says nothing either way and is skipped; prose ends the run
    /// of addresses; an address of the chain the last one was on, different
    /// from it, within the window, is a swap.
    pub fn observe(&mut self, text: &str, now: Instant) -> Option<Alert> {
        if text == self.last_text {
            return None;
        }
        self.last_text.clear();
        self.last_text.push_str(text);
        if text.trim().is_empty() {
            return None;
        }
        let Some((chain, token)) = the_address(text) else {
            self.last_address = None;
            return None;
        };
        let alert = match &self.last_address {
            Some(last)
                if last.chain == chain
                    && !same(chain, &last.text, token)
                    && now.duration_since(last.at) <= self.window =>
            {
                Some(Alert {
                    chain,
                    from: last.text.clone(),
                    to: token.to_string(),
                    after: now.duration_since(last.at),
                })
            }
            _ => None,
        };
        match &mut self.last_address {
            Some(last) if last.chain == chain && same(chain, &last.text, token) => {}
            _ => self.last_address = Some(Last { chain, text: token.to_string(), at: now }),
        }
        alert
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    pub window: Duration,
    pub interval: Duration,
    /// Stop after the first alert.
    pub once: bool,
}

/// Poll `read` every `interval` until it has nothing more, or, with
/// `once`, until the first alert; `alert` is called for each. Returns how
/// many there were.
pub fn run(
    read: &mut dyn FnMut() -> Option<String>,
    clock: &mut dyn FnMut() -> Instant,
    sleep: &dyn Fn(Duration),
    s: &Settings,
    alert: &mut dyn FnMut(&Alert),
) -> usize {
    let mut guard = Guard::new(s.window);
    let mut n = 0;
    while let Some(text) = read() {
        if let Some(a) = guard.observe(&text, clock()) {
            n += 1;
            alert(&a);
            if s.once {
                break;
            }
        }
        sleep(s.interval);
    }
    n
}

/// The guard over a scripted clipboard: one line of `script` per read, in
/// order, the clock advancing `interval` per read, no sleeping. This is
/// the `WPANTRY_CLIPBOARD_FAKE` test hook, and what the unit tests use.
pub fn run_script(script: &str, s: &Settings, alert: &mut dyn FnMut(&Alert)) -> usize {
    let lines: Vec<&str> = script.lines().collect();
    let base = Instant::now();
    let i = Cell::new(0usize);
    let mut read = || {
        let line = lines.get(i.get())?;
        i.set(i.get() + 1);
        Some(line.to_string())
    };
    // The read happens before the clock is asked, so read k is at k * interval.
    let mut clock = || base + s.interval * (i.get().saturating_sub(1) as u32);
    run(&mut read, &mut clock, &|_| {}, s, alert)
}

/// A desktop notification for the alert, where the desktop has them:
/// Notification Center on macOS (`osascript`), `notify-send` elsewhere.
/// Nothing happens where neither is available.
pub fn notify(a: &Alert) {
    let title = "wpantry: a copied wallet address was swapped";
    let body = format!(
        "{} became {} ({}). Don't send funds from this machine; if you copied two addresses yourself, ignore this.",
        a.from,
        a.to,
        a.chain.name()
    );
    let timeout = Duration::from_secs(10);
    if cfg!(target_os = "macos") {
        let script = format!("display notification {} with title {}", applescript(&body), applescript(title));
        let _ = process::exec(&[OsStr::new("osascript"), OsStr::new("-e"), OsStr::new(&script)], &[], timeout);
    } else if process::which("notify-send").is_some() {
        let _ = process::exec(
            &[OsStr::new("notify-send"), OsStr::new("--urgency=critical"), OsStr::new(title), OsStr::new(&body)],
            &[],
            timeout,
        );
    }
}

/// `s` as an AppleScript string literal.
fn applescript(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "0x52908400098527886E0F7030069857D2E4169EE7";
    const B: &str = "0xD62Eb957610d49f77cFce8bCc9827b5428D790E6";
    const BTC: &str = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    const TRON: &str = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t";

    fn settings(window_secs: f64, once: bool) -> Settings {
        Settings { window: Duration::from_secs_f64(window_secs), interval: INTERVAL, once }
    }

    /// The alerts a script raises, as (chain, from, to, seconds).
    fn alerts(script: &str, s: &Settings) -> Vec<(Chain, String, String, f64)> {
        let mut out = Vec::new();
        let n = run_script(script, s, &mut |a| {
            out.push((a.chain, a.from.clone(), a.to.clone(), (a.after.as_secs_f64() * 100.0).round() / 100.0))
        });
        assert_eq!(n, out.len());
        out
    }

    #[test]
    fn a_swap_within_the_window_alerts_with_both_addresses() {
        // Copied, held for three reads, then rewritten by a clipper.
        let script = format!("hello\n{A}\n{A}\n{A}\n{B}\n{B}\n");
        let got = alerts(&script, &settings(2.0, false));
        assert_eq!(got, [(Chain::Evm, A.to_string(), B.to_string(), 0.75)]);
        let note = Alert { chain: Chain::Evm, from: A.into(), to: B.into(), after: Duration::from_millis(750) }.note();
        assert!(note.contains(A) && note.contains(B) && note.contains("EVM"), "{note}");
        assert!(note.contains("If you copied two addresses yourself, ignore this"), "{note}");
    }

    #[test]
    fn a_double_copy_inside_the_window_is_the_named_false_positive() {
        let script = format!("{A}\n{B}\n");
        let got = alerts(&script, &settings(2.0, false));
        assert_eq!(got.len(), 1, "two addresses in a quarter second: the guard can't tell, and says so");
        // Outside the window it isn't one: 2 s is 8 reads at 250 ms.
        let script = format!("{A}\n{}{B}\n", format!("{A}\n").repeat(8));
        assert!(alerts(&script, &settings(2.0, false)).is_empty(), "2.25 s apart");
        let script = format!("{A}\n{}{B}\n", format!("{A}\n").repeat(7));
        assert_eq!(alerts(&script, &settings(2.0, false)).len(), 1, "exactly 2 s apart is inside");
        // A longer window catches the slower copy.
        let script = format!("{A}\n{}{B}\n", format!("{A}\n").repeat(8));
        assert_eq!(alerts(&script, &settings(5.0, false)).len(), 1);
    }

    #[test]
    fn prose_between_two_addresses_ends_the_run() {
        let script = format!("{A}\nmeeting notes for tuesday\n{B}\n");
        assert!(alerts(&script, &settings(2.0, false)).is_empty());
        // Prose alone, however much, is never an alert.
        let prose = "the quick brown fox\njumps over\n\n\nthe lazy dog\n".repeat(20);
        assert!(alerts(&prose, &settings(2.0, false)).is_empty());
        // An empty read (the tool failed, or an image is on the clipboard) says nothing and the run goes on.
        let script = format!("{A}\n\n\n{B}\n");
        assert_eq!(alerts(&script, &settings(2.0, false)).len(), 1);
    }

    #[test]
    fn only_the_same_chain_and_a_different_address_count() {
        let script = format!("{A}\n{BTC}\n{TRON}\n");
        assert!(alerts(&script, &settings(2.0, false)).is_empty(), "three chains: nothing swapped");
        let script = format!("{A}\n{}\n{A}\n", A.to_lowercase());
        assert!(alerts(&script, &settings(2.0, false)).is_empty(), "the same EVM address in another case");
        let script = format!("{BTC}\n{}\n", BTC.to_uppercase());
        assert_eq!(alerts(&script, &settings(2.0, false)).len(), 1, "bech32 is case-sensitive as a string: different");
        // The address inside a line counts, two in one text don't.
        let script = format!("pay {A} today\npay {B} today\n");
        assert_eq!(alerts(&script, &settings(2.0, false)).len(), 1);
        let script = format!("{A}\n{A} or {B}\n{B}\n");
        assert!(alerts(&script, &settings(2.0, false)).is_empty(), "a text with two addresses is prose");
    }

    #[test]
    fn once_stops_at_the_first_alert_and_the_time_is_kept_from_the_first_copy() {
        let script = format!("{A}\n{B}\n{A}\n{B}\n");
        assert_eq!(alerts(&script, &settings(2.0, true)).len(), 1);
        assert_eq!(alerts(&script, &settings(2.0, false)).len(), 3);
        // Re-reading the same address doesn't restart the clock.
        let mut g = Guard::new(Duration::from_secs(2));
        let t0 = Instant::now();
        assert!(g.observe(A, t0).is_none());
        assert!(g.observe(&format!("{A}\n"), t0 + Duration::from_millis(1900)).is_none(), "trailing newline: same");
        let a = g.observe(B, t0 + Duration::from_millis(2000)).expect("a swap");
        assert_eq!(a.after, Duration::from_millis(2000), "measured from the first time A was seen");
        assert!(g.observe(B, t0 + Duration::from_millis(2100)).is_none(), "unchanged");
    }

    #[test]
    fn the_event_json_and_the_cache_record() {
        let a = Alert { chain: Chain::Tron, from: TRON.into(), to: TRON.into(), after: Duration::from_millis(333) };
        let v = a.to_json(1_793_348_743.0);
        assert_eq!(v["event"], "clipper");
        assert_eq!(v["schema"], crate::SCHEMA);
        assert_eq!(v["chain"], "Tron");
        assert_eq!(v["seconds"], 0.33);
        assert_eq!(v["at"], 1_793_348_743.0);
        let d = crate::utils::temp::TempDir::new("guard").unwrap();
        let c = Cache::open(Some(&d.path().join("w.db"))).unwrap();
        record(&c, &a).unwrap();
        let events = history::events(&c, 0.0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "clipper");
        assert_eq!(events[0].detail["to"], TRON);
        assert!(events[0].detail.get("schema").is_none(), "the envelope keys stay out of the table");
        c.close().unwrap();
        assert_eq!(applescript("say \"hi\" \\ bye"), "\"say \\\"hi\\\" \\\\ bye\"");
    }
}
