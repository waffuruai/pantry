//! The automation client and the suite's oracles. `Driver` runs
//! `wpantry-desktop --automation` (never a window) and speaks its JSON Lines
//! protocol; `Ctx` is one scenario's throwaway home, cache and environment.
//!
//! ```text
//! let ctx = Ctx::new("example");
//! let mut driver = Driver::start(&app(), Some(&scanner), &ctx.env);
//! assert_eq!(driver.settled()["report"], Value::Null);
//! driver.close();
//! ```

use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::{Duration, Instant};

/// How long one reply may take. Scans of an empty folder and fixes by the
/// stand-ins finish in seconds; this only turns a hang into a failure.
const REPLY_TIMEOUT: Duration = Duration::from_secs(180);

pub fn app() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wpantry-desktop"))
}

pub fn standin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wpantry-standin"))
}

/// Environment overrides on top of the test process's own, as the Python
/// suite's `dict(os.environ, ...)`. Kept as overrides so Windows' case-
/// insensitive names (`Path` vs `PATH`) resolve the way the OS does.
#[derive(Clone, Default)]
pub struct Env(BTreeMap<String, OsString>);

impl Env {
    pub fn set(&mut self, key: &str, value: impl AsRef<OsStr>) {
        self.0
            .insert(key.to_string(), value.as_ref().to_os_string());
    }

    pub fn with(&self, pairs: &[(&str, &OsStr)]) -> Env {
        let mut env = self.clone();
        for (key, value) in pairs {
            env.set(key, value);
        }
        env
    }

    pub fn get(&self, key: &str) -> Option<OsString> {
        self.0.get(key).cloned().or_else(|| std::env::var_os(key))
    }

    pub fn path(&self, key: &str) -> PathBuf {
        PathBuf::from(self.get(key).unwrap_or_else(|| panic!("{key} is not set")))
    }

    /// Put `dir` first on PATH.
    pub fn prepend_path(&mut self, dir: &Path) {
        let mut paths = vec![dir.to_path_buf()];
        paths.extend(std::env::split_paths(&self.get("PATH").unwrap_or_default()));
        self.set("PATH", std::env::join_paths(paths).expect("PATH joins"));
    }

    pub fn apply(&self, command: &mut Command) {
        command.envs(&self.0);
    }
}

/// One scenario's root folder, under Cargo's per-target temp directory. It
/// is removed when the scenario passes and kept (its path printed) when it
/// fails. Only a folder this suite made is ever removed.
pub struct TempRoot(PathBuf);

impl TempRoot {
    fn new(name: &str) -> TempRoot {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        let path = base.join(format!(
            "pantry-desktop-tests-{name}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create the test folder");
        TempRoot(path)
    }
}

impl Drop for TempRoot {
    fn drop(&mut self) {
        let base = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        let ours = self.0.starts_with(&base)
            && self
                .0
                .file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|n| n.starts_with("pantry-desktop-tests-"));
        if std::thread::panicking() || std::env::var_os("PANTRY_E2E_KEEP").is_some() || !ours {
            eprintln!("Kept the test folder {}", self.0.display());
        } else {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

/// A scenario's home: HOME and the cache in a fresh folder, no update
/// checks, no colour, as every check of the suite expects.
pub struct Ctx {
    pub temp: PathBuf,
    pub env: Env,
    _root: TempRoot,
}

impl Ctx {
    pub fn new(name: &str) -> Ctx {
        let root = TempRoot::new(name);
        let temp = root.0.clone();
        let mut env = Env::default();
        env.set("HOME", &temp);
        env.set("USERPROFILE", &temp);
        env.set("WPANTRY_DB", temp.join("pantry.db"));
        env.set("XDG_STATE_HOME", temp.join("state"));
        env.set("XDG_CONFIG_HOME", temp.join("config"));
        env.set("WPANTRY_NO_UPDATE_CHECK", "1");
        env.set("NO_COLOR", "1");
        Ctx {
            temp,
            env,
            _root: root,
        }
    }

    /// Only the scheduler is faked (macOS and Linux; Windows skips the
    /// schedule checks). The real scanner still writes and reads its
    /// launch-agent or timer files in the fixture directory. Returns the
    /// folder of the stand-ins.
    pub fn fake_scheduler(&mut self) -> Option<PathBuf> {
        if cfg!(windows) {
            return None;
        }
        let tools = self.temp.join("bin");
        std::fs::create_dir(&tools).expect("create the tools folder");
        #[cfg(unix)]
        {
            crate::tools::write_script(&tools.join("launchctl"), crate::tools::LAUNCHCTL);
            crate::tools::write_script(&tools.join("systemctl"), "#!/bin/sh\nexit 0\n");
        }
        self.env.prepend_path(&tools);
        self.env.set("XDG_RUNTIME_DIR", self.temp.join("runtime"));
        Some(tools)
    }
}

pub struct Driver {
    child: Child,
    stdin: Option<ChildStdin>,
    lines: Receiver<String>,
}

impl Driver {
    pub fn start(app: &Path, scanner: Option<&Path>, env: &Env) -> Driver {
        let mut command = Command::new(app);
        command.arg("--automation");
        if let Some(scanner) = scanner {
            command.arg("--scanner").arg(scanner);
        }
        env.apply(&mut command);
        command.stdin(Stdio::piped()).stdout(Stdio::piped());
        let mut child = command
            .spawn()
            .unwrap_or_else(|e| panic!("start {}: {e}", app.display()));
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().expect("stdout");
        let (send, lines) = channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                if send.send(line).is_err() {
                    break;
                }
            }
        });
        Driver {
            child,
            stdin,
            lines,
        }
    }

    fn send(&mut self, op: &str, fields: Value, succeeds: bool) -> Value {
        let mut message = if fields.is_null() {
            json!({})
        } else {
            fields.clone()
        };
        message["op"] = json!(op);
        let stdin = self.stdin.as_mut().expect("the driver is open");
        writeln!(stdin, "{message}")
            .and_then(|()| stdin.flush())
            .expect("send a request");
        let line = self
            .lines
            .recv_timeout(REPLY_TIMEOUT)
            .unwrap_or_else(|_| panic!("Desktop stopped before answering {op}."));
        let reply: Value = serde_json::from_str(&line)
            .unwrap_or_else(|e| panic!("reply is not JSON ({e}): {line}"));
        assert_eq!(reply["ok"], json!(succeeds), "{op} {fields} {reply}");
        reply[if succeeds { "result" } else { "error" }].clone()
    }

    /// A request that must succeed; its result.
    pub fn ok(&mut self, op: &str, fields: Value) -> Value {
        self.send(op, fields, true)
    }

    /// A request that must be refused; its error.
    pub fn refused(&mut self, op: &str, fields: Value) -> Value {
        self.send(op, fields, false)
    }

    pub fn click(&mut self, widget: &str) -> Value {
        self.ok("click", json!({"id": widget}))
    }

    /// A click on a widget that is not there (or not clickable).
    pub fn click_refused(&mut self, widget: &str) -> Value {
        self.refused("click", json!({"id": widget}))
    }

    /// The typed dispatcher: `action` plus its fields.
    pub fn action(&mut self, action: &str, fields: Value) -> Value {
        self.ok("dispatch", json!({"command": with_action(action, fields)}))
    }

    pub fn action_refused(&mut self, action: &str, fields: Value) -> Value {
        self.refused("dispatch", json!({"command": with_action(action, fields)}))
    }

    pub fn key(&mut self, key: &str, command: bool) -> Value {
        self.ok("key", json!({"key": key, "command": command}))
    }

    pub fn set_value(&mut self, widget: &str, value: &str) -> Value {
        self.ok("set_value", json!({"id": widget, "value": value}))
    }

    pub fn resize(&mut self, width: u32, height: u32) {
        self.ok("resize", json!({"width": width, "height": height}));
    }

    pub fn scroll_into_view(&mut self, widget: &str) {
        self.ok("scroll_into_view", json!({"id": widget}));
    }

    /// Wait for the running task; the state after it.
    pub fn settled(&mut self) -> Value {
        self.ok("wait", Value::Null)["state"].clone()
    }

    pub fn state(&mut self) -> Value {
        self.ok("state", Value::Null)
    }

    pub fn tree(&mut self) -> Vec<Value> {
        match self.ok("tree", Value::Null) {
            Value::Array(nodes) => nodes,
            other => panic!("tree is not a list: {other}"),
        }
    }

    /// The one widget with this id.
    pub fn widget(&mut self, widget: &str) -> Value {
        let nodes: Vec<Value> = self
            .tree()
            .into_iter()
            .filter(|n| n["id"] == widget)
            .collect();
        assert_eq!(nodes.len(), 1, "{widget}: {nodes:?}");
        nodes[0].clone()
    }

    /// Whether any widget carries this id.
    pub fn has_widget(&mut self, widget: &str) -> bool {
        self.tree().iter().any(|n| n["id"] == widget)
    }

    pub fn label(&mut self, widget: &str) -> String {
        self.widget(widget)["label"]
            .as_str()
            .unwrap_or("")
            .to_string()
    }

    pub fn labels(&mut self) -> Vec<String> {
        self.tree()
            .iter()
            .map(|n| n["label"].as_str().unwrap_or("").to_string())
            .collect()
    }

    /// Whether any label contains `text`.
    pub fn has_label(&mut self, text: &str) -> bool {
        self.labels().iter().any(|label| label.contains(text))
    }

    /// Close stdin, as a person closing the window; the app must exit 0.
    pub fn close(mut self) {
        drop(self.stdin.take());
        let status = wait_exit(&mut self.child, Duration::from_secs(15))
            .expect("the desktop exits after stdin closes");
        assert!(status.success(), "the desktop exited with {status}");
    }

    /// Close stdin and wait for the app, without judging its status.
    #[cfg(unix)]
    pub fn close_stdin(&mut self) {
        drop(self.stdin.take());
        wait_exit(&mut self.child, Duration::from_secs(15))
            .expect("the desktop exits after stdin closes");
    }
}

impl Drop for Driver {
    /// A failed check still leaves no desktop running.
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(Some(_))) {
            return;
        }
        drop(self.stdin.take());
        if wait_exit(&mut self.child, Duration::from_secs(15)).is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn with_action(action: &str, fields: Value) -> Value {
    let mut command = if fields.is_null() { json!({}) } else { fields };
    command["action"] = json!(action);
    command
}

fn wait_exit(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Poll `done` every 50 ms for up to ten seconds.
#[cfg(unix)]
pub fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !done() {
        assert!(Instant::now() < deadline, "{what}");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[cfg(unix)]
pub fn pid_alive(pid: u32) -> bool {
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Read a pid file the stand-in wrote.
#[cfg(unix)]
pub fn read_pid(path: &Path) -> u32 {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    text.trim()
        .parse()
        .unwrap_or_else(|_| panic!("pid file {}: {text:?}", path.display()))
}

pub fn read_json(path: &Path) -> Value {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}
