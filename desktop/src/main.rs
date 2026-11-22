#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

mod app;
mod automation;
mod brand;
mod data;
mod explain;
mod pantry;
mod view;

use eframe::egui;
use std::ffi::OsString;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::Command;
use wpantry_desktop::instance;

/// Show a startup failure where people can see it. A release build on
/// Windows has no console, and an app opened from Finder or a desktop menu
/// has nowhere visible for stderr, so use the system's own dialog. Follows
/// `wpantry-setup`'s `main`.
fn alert(message: &str) {
    eprintln!("Pantry: {message}");
    if std::io::stderr().is_terminal() {
        return;
    }
    #[cfg(windows)]
    let _ = {
        use std::os::windows::process::CommandExt;
        Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-WindowStyle",
                "Hidden",
                "-Command",
                "Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show($env:PANTRY_ERROR, 'Pantry')",
            ])
            .env("PANTRY_ERROR", message)
            .creation_flags(0x08000000)
            .status()
    };
    #[cfg(target_os = "macos")]
    let _ = Command::new("osascript")
        .args([
            "-e",
            "on run argv",
            "-e",
            "display alert \"Pantry could not open\" message (item 1 of argv)",
            "-e",
            "end run",
            "--",
            message,
        ])
        .status();
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let shown = Command::new("zenity")
            .args(["--error", "--title=Pantry", "--text", message])
            .status()
            .is_ok_and(|s| s.success())
            || Command::new("kdialog")
                .args(["--title", "Pantry", "--error", message])
                .status()
                .is_ok_and(|s| s.success());
        let _ = shown;
    }
}

/// Turn a window-system error into a sentence with something to try.
fn startup_message(error: &dyn std::fmt::Display) -> String {
    let raw = error.to_string();
    let lower = raw.to_lowercase();
    let hint = if lower.contains("opengl")
        || lower.contains("gl ")
        || lower.contains("glutin")
        || lower.contains("egl")
    {
        "Pantry needs OpenGL graphics to draw its window. Update your graphics driver, or on Linux install your distribution's Mesa packages."
    } else if lower.contains("display") || lower.contains("wayland") || lower.contains("x11") {
        "Pantry could not find a desktop to open its window on."
    } else {
        "Pantry could not open its window."
    };
    format!("{hint}\n\nDetails: {raw}")
}

const USAGE: &str = "Usage: wpantry-desktop [--scanner PATH] [--automation | --scheduled-run]

  --scanner PATH    use this wpantry scanner instead of the one beside the app
  --automation      drive the app headless over standard input (tests)
  --scheduled-run   run the scanner's `schedule run` with no window and exit
                    with its code (the Windows scheduled scan starts this)
  --version         print the version
  --help            print this help";

/// What the command line asks for.
#[derive(Debug, PartialEq)]
enum Launch {
    /// Open the window, or drive the app headless with `--automation`.
    App {
        scanner: Option<PathBuf>,
        automate: bool,
    },
    /// Run the scanner's `schedule run` with no window and exit with its
    /// code. Task Scheduler starts this on Windows so no console flashes.
    ScheduledRun {
        scanner: Option<PathBuf>,
    },
    Version,
    Help,
}

/// Parse the arguments after the program name. `--scheduled-run` combines
/// only with `--scanner`.
///
/// ```ignore
/// parse(["--scheduled-run"]) == Ok(Launch::ScheduledRun { scanner: None })
/// parse(["--scheduled-run", "--automation"]) // Err
/// ```
fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Launch, String> {
    let mut args = args.into_iter();
    let (mut scanner, mut automate, mut scheduled) = (None, false, false);
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--scanner") => scanner = Some(pantry::explicit(&mut args, &arg)?),
            Some("--automation") => automate = true,
            Some("--scheduled-run") => scheduled = true,
            Some("--version") => return Ok(Launch::Version),
            Some("--help") => return Ok(Launch::Help),
            _ => return Err(format!("Unknown argument: {}", arg.to_string_lossy())),
        }
    }
    match (scheduled, automate) {
        (true, true) => Err("--scheduled-run cannot be combined with --automation.".into()),
        (true, false) => Ok(Launch::ScheduledRun { scanner }),
        (false, _) => Ok(Launch::App { scanner, automate }),
    }
}

/// Start the scanner's `schedule run` and wait for it. On Windows the
/// scanner is a console program, so it starts with CREATE_NO_WINDOW and its
/// console (shared by the sync and scan it starts) stays hidden. This never
/// claims the window lock, so it runs while Pantry is open, and it never
/// shows a dialog: the outcome goes to the schedule log and the exit code.
fn scheduled_run(scanner: Option<PathBuf>) -> std::process::ExitCode {
    let pantry = pantry::Pantry::locate(scanner);
    if !pantry.found {
        eprintln!("Pantry: no scanner at {}", pantry.path.display());
        return std::process::ExitCode::FAILURE;
    }
    let mut command = Command::new(&pantry.path);
    command
        .args(["schedule", "run"])
        .stdin(std::process::Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        command.creation_flags(CREATE_NO_WINDOW);
    }
    match command.status() {
        // A scanner killed by a signal has no code: report a failure.
        Ok(status) => std::process::ExitCode::from(
            status
                .code()
                .and_then(|code| u8::try_from(code).ok())
                .unwrap_or(1),
        ),
        Err(error) => {
            eprintln!("Pantry: could not start {}: {error}", pantry.path.display());
            std::process::ExitCode::FAILURE
        }
    }
}

fn main() -> std::process::ExitCode {
    let args: Vec<OsString> = std::env::args_os().skip(1).collect();
    // A scheduled run never shows a dialog, not even for a bad argument.
    let quiet = args
        .iter()
        .any(|arg| arg == "--automation" || arg == "--scheduled-run");
    let result = match parse(args) {
        Ok(Launch::ScheduledRun { scanner }) => return scheduled_run(scanner),
        Ok(Launch::Version) => {
            println!("wpantry-desktop {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Ok(Launch::Help) => {
            println!("{USAGE}");
            Ok(())
        }
        Ok(Launch::App { scanner, automate }) => run(scanner, automate),
        Err(error) => Err(error),
    };
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(error) => {
            if quiet {
                eprintln!("Pantry: {error}");
            } else {
                alert(&error);
            }
            std::process::ExitCode::FAILURE
        }
    }
}

fn run(scanner: Option<PathBuf>, automate: bool) -> Result<(), String> {
    let pantry = pantry::Pantry::locate(scanner);
    if automate {
        return automation::run(pantry).map_err(|e| e.to_string());
    }
    let (state, _) = instance::directories()
        .map_err(|e| format!("Pantry could not find its settings folder. {e}"))?;
    let Some(instance) =
        instance::Instance::claim(&state).map_err(|e| format!("Pantry could not start. {e}"))?
    else {
        return Ok(());
    };
    let settings_path = state.join("settings.json");
    let size = app::Settings::load(&settings_path).window_size();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("Pantry")
            .with_icon(brand::window_icon())
            .with_inner_size(size)
            .with_min_inner_size(app::Settings::MIN_WINDOW),
        ..Default::default()
    };
    eframe::run_native(
        "ai.waffuru.pantry.desktop",
        options,
        Box::new(move |cc| {
            view::setup(&cc.egui_ctx, true);
            Ok(Box::new(NativeApp {
                app: app::App::new(pantry, &cc.egui_ctx, Some(settings_path), false),
                instance,
                focused: true,
            }))
        }),
    )
    .map_err(|error| startup_message(&error))
}

struct NativeApp {
    app: app::App,
    instance: instance::Instance,
    focused: bool,
}

impl eframe::App for NativeApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.app.poll(false);
        let (focused, size) = ctx.input(|i| {
            let viewport = i.viewport();
            (
                viewport.focused.unwrap_or(true),
                viewport.inner_rect.map(|r| r.size()),
            )
        });
        if let Some(size) = size {
            self.app.remember_window(size);
        }
        // Coming back to the window, or every 10 seconds: pick up results
        // a scheduled scan wrote meanwhile.
        self.app.watch(ctx, focused && !self.focused);
        self.focused = focused;
        if self.instance.activation_requested() {
            ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                egui::UserAttentionType::Informational,
            ));
        }
        let every = if self.app.busy().is_some() { 250 } else { 750 };
        ctx.request_repaint_after(std::time::Duration::from_millis(every));
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        view::draw(ui, &mut self.app);
    }

    /// Closing the window: save settings and stop a running scan or fix
    /// (eframe may never drop the app on some platforms).
    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        self.app.flush_settings();
        self.app.shutdown();
    }
}

#[cfg(test)]
mod tests {
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
}
