# Pantry Desktop

The guide for people using the app is [docs/public/desktop.md](../docs/public/desktop.md); installing, updating and removing it is in [install.md](../docs/public/install.md#download-pantry-setup). This page is the reference for developers: what the app does, building it, and driving it from tests.

Open Pantry to see whether this computer needs anything. The home page answers three questions: are you OK, what is wrong, and how to fix it. The headline says how many things need your attention, with the time of the last scan in your local time. Each row is one plain sentence with how serious it is, in words and a shape as well as a colour. Problems attackers are using come first, then by severity, with the ones Pantry can fix first. Less urgent rows sit under **Show lower priority**. The headline counts only the latest scan. Problems an earlier scan of another folder found, and no scan has cleared, sit apart under **From earlier scans**, each with **Scan that folder again** and **Dismiss**. If that folder is gone, Pantry says so and offers only **Dismiss**. Dismissing only hides a problem in this window (the list is kept in `settings.json`); the scanner's history keeps it, and **Latest scan** lists the dismissed ones with **Show again**.

**Fix it** on a row shows what Pantry will change and asks once. After **Yes, fix it**, Pantry runs the fix, scans the same folders again and says **Fixed and checked**, **Still open**, or, when it could not read the results again, **Could not confirm. Scan again.** **Fix all N that Pantry can fix** does the same for every fix Pantry can run: one confirm (**Show the commands** shows each exact command, Esc or **Not now** closes it), then one fix at a time with a result for each and **Show details** on any that did not work, then one check scan. A newer scan clears a confirm that was waiting. Rows Pantry can't fix have **Show me how**, with numbered steps (including how to open a terminal) and a **Copy** button. Pantry never changes anything without your OK.

The first time, Pantry explains what it checks, what it won't do and, on macOS, how to let it read Documents, Desktop and Downloads. **Run first scan** starts. **Scan now** scans again at any time, and **Cancel** stops a scan or fix that is running; the results stay as they were, and a stopped fix says it may have partly run and offers **Scan now**. Scans stop after 30 minutes and fixes after 15. Closing the window stops a running scan or fix. A SIGTERM or SIGKILL sent to Pantry itself does not: Pantry has no signal handler, and the scanner runs in its own process group, so it keeps running until it finishes. The 30 and 15 minute limits are enforced by the app, so they end with it. Under `--automation`, closing stdin stops a running scan or fix.

Each finding's page says in one plain sentence what the flaw could let someone do (from its CWE weakness type, else its summary's words, else a neutral sentence), whether CISA lists it as used in attacks, its security notice IDs as links with **Copy ID**, and the notice's own summary. **Show technical details** in the sidebar adds commands, affected and fixed versions, CVSS, EPSS, the weakness type, versions, folders and scan numbers, plus **Reload results**. **Latest scan** lists everything the last scan saw. Folders you chose to skip show once as "Skipped by your choice: personal folders" with a checkbox to include them; they never count as unfinished checks. A check that really could not finish says why and has **Retry**. **History** shows recent scans, fixes and confirmed fixes. Errors appear in plain words with **Show details** for the scanner's own text. Pantry reloads results when a scheduled scan finishes while the window is open.

Use **Scan schedule** to choose how often Pantry scans. Scheduled scans use launchd on macOS, a user timer or cron on Linux, and Task Scheduler on Windows while you are signed in. They refresh security notices and scan.

Pantry remembers the theme (it follows your system until you pick one), the personal folders choice, technical details, the last page and the window size in `settings.json` in its state folder. Keyboard: Esc goes back or closes, Cmd+R (Ctrl+R) scans, Cmd+F (Ctrl+F) searches.

The sidebar links to the Pantry GitHub repository and support@waffuru.ai.

## Install and update

Download Pantry Setup from the [latest Pantry release](https://github.com/waffuruai/pantry/releases/latest). Open **Pantry Setup.exe** on Windows. On macOS, extract the download and open **Pantry Setup**. On Linux, extract the download and open **pantry-setup.desktop** (in GNOME Files, right-click it and choose Allow Launching first), or run `./"Pantry Setup"` in that folder. If extracting dropped the permissions, run `chmod +x "Pantry Setup" pantry-setup.desktop` first. No AppImage is offered: it would need FUSE, which Ubuntu 24.04 no longer installs by default, and a browser download loses the executable bit either way.

Setup installs the desktop app and its matching scanner for your user account, then opens Pantry. On Windows it adds Pantry to the Start menu. On Linux it adds Pantry to the app menu (`~/.local/share/applications/ai.waffuru.pantry.desktop` with its icon). On macOS, `~/Applications/Pantry/Pantry.app` shows in Launchpad and Spotlight. The app reads the same local results, history and schedule as the CLI. It also works as a portable app from the desktop ZIP.

If Pantry is open and the installed version is older, Setup says so and changes nothing: quit Pantry, then run Setup again. If Pantry is open and already up to date, Setup brings its window forward. A second copy of Setup started while one is running says Setup is already running and changes nothing. Running the same version again repairs the install (a missing or damaged file comes back). An older Setup over a newer install says "A newer Pantry is already installed.", keeps it, and opens it.

To remove Pantry, quit it and run Setup with `--uninstall` (on macOS, `"Pantry Setup.app/Contents/MacOS/Pantry Setup" --uninstall`). Setup first moves the install folder aside and deletes it; if any file cannot be deleted, it puts the rest back with its marker file, says why (Pantry in use, or no permission), and changes nothing else, so Setup can repair or remove it later. Only then does it remove Pantry's scheduled scan, which is the one scheduled scan per account that the app and the CLI share: through the installed scanner, or directly (the launchd job, systemd user timer or Windows task) if the scanner is missing or fails. If a scheduled scan may remain, Setup says so and how to remove it. Last it removes the Start menu or app menu entry. It only removes a folder that holds its marker file. If nothing is installed, Setup says so. Your scan history, settings and cache stay.

| Computer | Installer | Installed app |
| --- | --- | --- |
| Mac with Apple silicon or Intel | `wpantry-setup-universal-apple-darwin.zip` | `~/Applications/Pantry/Pantry.app` |
| Linux x86-64 | `wpantry-setup-x86_64-unknown-linux-gnu.tar.gz` | `~/.local/share/pantry-desktop/wpantry-desktop` |
| Linux arm64 | `wpantry-setup-aarch64-unknown-linux-gnu.tar.gz` | `~/.local/share/pantry-desktop/wpantry-desktop` |
| Windows x86-64 | `wpantry-setup-x86_64-pc-windows-msvc.exe` | `%LOCALAPPDATA%\Programs\Pantry\wpantry-desktop.exe` |

Verify your download before running it. The same release carries the following portable ZIPs.

| Computer | ZIP |
| --- | --- |
| Mac with Apple silicon or Intel | `wpantry-desktop-universal-apple-darwin.zip` |
| Linux x86-64 | `wpantry-desktop-x86_64-unknown-linux-gnu.zip` |
| Linux arm64 | `wpantry-desktop-aarch64-unknown-linux-gnu.zip` |
| Windows x86-64 | `wpantry-desktop-x86_64-pc-windows-msvc.zip` |

Verify the ZIP before extracting it. Pantry can copy the download and verification commands for an available update. With [GitHub CLI](https://cli.github.com/) installed and authorized, substitute the filename and tag you downloaded.

```sh
gh attestation verify wpantry-desktop-universal-apple-darwin.zip --repo waffuruai/pantry --signer-workflow waffuruai/pantry/.github/workflows/release.yml --source-ref refs/tags/vX.Y.Z
```

Open **Pantry.app** on macOS, **wpantry-desktop.exe** on Windows, or run **./wpantry-desktop** from the extracted folder on Linux. The Linux bundle needs a GNU/Linux desktop with X11 or Wayland and OpenGL. It is built on Ubuntu 24.04. Other Linux systems can build from source against their own libraries. Keep the scanner beside the app on Linux and Windows. The Mac app bundle contains its scanner.

GitHub release attestation verifies the archive's origin. The Mac app is signed ad hoc and the Windows executables are not signed yet, so both systems warn the first time; [install.md](../docs/public/install.md#if-your-computer-warns-about-the-download) says how to proceed safely.

Choose **Check for updates** in Pantry to find the latest installer for your platform. When Pantry can't reach GitHub and only has an older answer, it says "Could not check for updates. Last checked" with the date, and never "You're up to date". Verify the download, then quit Pantry and run Setup again. If you use the portable ZIP, replace the app and its scanner together. If you move the app, save the schedule again to point it at the scanner's new location.

## Build from this checkout

To build release binaries, package them like a release and install them with Pantry Setup, run `desktop/release/install-local.sh` (`--open` to open Pantry after, `--no-install` to leave the files in `desktop/dist/`, `--help`). Prerequisites per platform are in [Build it yourself](../docs/public/install.md#build-it-yourself). With `WPANTRY_DESKTOP_HOME` set, Setup installs into that folder instead; CI uses that.

For a debug build, use the pinned Rust toolchain in each directory on macOS, Linux or Windows. Commands below use Bash, including Git Bash on Windows. Add `.exe` to the two binary names on Windows.

```sh
(cd rust && cargo build --locked -p wpantry-cli)
(cd desktop && cargo build --locked)
desktop/target/debug/wpantry-desktop --scanner rust/target/debug/wpantry
```

On Windows the scheduled scan's task starts `wpantry-desktop.exe --scheduled-run`, a hidden flag that runs the scanner beside it with `schedule run` and no console window, waits, and exits with the scanner's code. It never opens a window or takes the window lock, so it also runs while Pantry is open. It works on every platform and is in `--help`.

Pantry uses the `--scanner` path when provided, then the scanner beside the executable (inside `Pantry.app/Contents/MacOS` on macOS). Debug builds also look on PATH; release builds never do, so they can't pick up a scanner from another version. The desktop dependencies have their own lockfile. The scanner, data and command contracts live in the existing Rust workspace.

## Automate or test

Every interactive control has an AccessKit author ID. Use your platform's accessibility driver for a visible window. The same egui view and action dispatcher run without a display over a JSON Lines protocol on standard input and output.

```sh
desktop/target/debug/wpantry-desktop --scanner rust/target/debug/wpantry --automation
```

Send one object per line. Each response contains `ok` and either `result` or `error`.

```jsonl
{"op":"wait"}
{"op":"tree"}
{"op":"click","id":"nav.results"}
{"op":"set_value","id":"findings.search","value":"openssl"}
{"op":"dispatch","command":{"action":"scan","path":"/path/to/project","offline":true}}
{"op":"key","key":"Escape"}
{"op":"scroll_into_view","id":"theme.toggle"}
{"op":"cancel"}
{"op":"screenshot","path":"/tmp/home.png","scale":2}
```

- `tree` returns every widget with an automation ID, label, role, enabled state, bounds and whether it is interactive. The suite fails if an interactive widget has no ID or two share one.
- `click` and `set_value` send real AccessKit actions to those widgets. `key` presses a key (`Escape`, or `R` or `F` with `"command": true`).
- `wait` returns when the current task ends, including by cancel or the time limit. `cancel` stops it and its child processes. `set_time_limit` (`milliseconds`, 0 for the normal limits) shortens every task's limit for tests.
- `scroll_into_view` scrolls the scroll area that holds a widget until the widget shows, as a screen reader does. The sidebar reports its visible area as a `ScrollView` node with the ID `sidebar.scroll`; the suite checks that at 820 by 480 every sidebar control can be scrolled inside it, above the pinned help links.
- `resize` draws at another size, such as the 820 by 480 minimum. `screenshot` renders the current frame to a PNG on the CPU, with no window and no GPU.
- `state` returns the window's state: page, filter, selection, report, friendly error (`summary`, `kind`, raw `details`), the confirm step and its command, the result after a fix (`fix_result`), the Fix all batch with each item's status, settings, plus `busy`, `busy_note` (the scanner's last status line), `slow`, `cancellable`, `mode` (`first_run` or `has_report`), `palette`, `fixable`, `search_focused`, `headline_count` (the latest scan's open problems), `rows` (for each home row drawn, `{lines, cut}`: how many lines its sentence took and whether it was cut short) and `earlier` (each `{id, component, scope, dismissed, missing_folders}`). Scanner text is shown and returned without control or bidirectional override characters. The earlier group's controls carry `earlier.<id>`, `earlier.<id>.rescan`, `earlier.<id>.dismiss`, `earlier.<id>.missing`, `earlier.<id>.how` and `earlier.<id>.restore`. With a finding selected, `finding` gives its `sentence`, `explanation`, `explanation_source` (`cwe`, `keyword`, `kind` or `generic`), `attacks`, `identifiers` (each `{id, url}`), `summary` and `cwe`. `open_advisory` (`id`, one of the finding's identifiers) opens that notice and `copy_id` copies the first identifier; the advisory links carry `finding.advisory.<ID>` and the button `finding.copy_id`. Clipboard and browser outputs are returned to the driver instead of being opened.
- `dispatch` calls the [typed action dispatcher](src/app.rs) directly. Actions: `refresh`, `scan` (`path`, `offline`, `include_personal_files`), `retry` (scan the latest scope again), `cancel`, `show` (`page`), `search` (`text`), `set_filter` (`all` or `fixable`), `select` (`id`), `close_finding`, `show_lower_priority` (`open`), `fix_it` (also `preview_fix`), `confirm_fix`, `cancel_fix`, `toggle_fix_details`, `copy_fix`, `fix_all`, `confirm_fix_all`, `cancel_fix_all`, `dismiss_fix_all`, `dismiss_fix_result`, `dismiss_error`, `toggle_error_details`, `rescan_earlier` (`id`), `dismiss_earlier` (`id`), `restore_earlier` (`id`), `toggle_batch_details` (`id`), `copy_watch_command`, `set_light` (`light`), `set_theme` (`system`, `light`, `dark`), `set_details` (`on`), `set_personal_files` (`include`), `open_scan_access`, `edit_schedule` (`open`), `set_period` (`every`), `set_time` (`at`, HH:MM), `save_schedule`, `remove_schedule`, `check_cache`, `check_updates`, `copy_update`, `open_release`, `open_download`, `open_github`, `open_support`.

Run the suite against an isolated cache with both binaries built.

```sh
python3 desktop/tests/e2e.py desktop/target/debug/wpantry-desktop rust/target/debug/wpantry
xvfb-run -a python3 desktop/tests/native_smoke.py desktop/target/debug/wpantry-desktop rust/target/debug/wpantry
```

The first command runs on all three operating systems and never opens a window. It covers first run, the schedule dropdowns, both palettes, Fix it with its check scan, Fix all, a missing scanner, settings that survive a restart or a damaged file, and (on macOS and Linux) Cancel, the time limit, a machine-scope fix with personal folders skipped, and the outcome checks (a fix that leaves its finding behind, a failed Fix all item, a reload that fails after a fix, a cancelled reload or fix, a newer scan clearing a confirm, the earlier-scans group, scanner text with bidi overrides, garbage output, an old update answer, a fix preview with a hidden character or for another scan, Cancel during Fix all, Scan with saved data repeating the failed scan, a background reload under a banner, Fix it while the results could not be read, a scan that could not read the attack list, Dismiss and Show again saved to `settings.json`, a schedule removal whose bootout failed shown as still registered with Remove it (macOS), a fix preview with extra words getting the plain "run one command" sentence with the command shown, each fix outcome told once, every Latest scan row reachable at 820 x 480 even far below the fold, the demo High row wrapping onto two lines at 820 x 480, and closing stdin while a scan runs), against stand-in scanners. The stand-in `launchctl` remembers whether the job is loaded, so `launchctl print` fails once it is removed, as the real one does. The machine case checks that skipped folders are not counted as unfinished checks and that the fix reads as fixed and checked; its twin adds one real unfinished check and must not. It also accepts `--bundle ZIP` and `--setup INSTALLER`. Add `--screens DIR` to save PNGs of each main screen in dark and light instead of running the checks. The second checks native window startup and reuse on Linux. Setup accepts `--install-only` for automation.
