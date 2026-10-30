# Suspicious code

Some code is written to be hard to read, to do more than it says, or to make a reviewer (a person or an AI) look away. wpantry reads the repos' own source and, on a machine scan, every editor extension, agent plugin and browser extension installed, for the shapes those take. None of them is wrong on its own, so the verdict depends on where the pattern sits: what is routine in one language or place is out of place in another. A finding **fails** where it is out of place, **warns** elsewhere, and a policy file can turn any id or path into a warning for good. Nothing is ever silenced.

| Id | What | Fails when | Warns when |
|---|---|---|---|
| `EXEC-DECODED` | `eval`, `new Function`, `setTimeout("…")`, `exec`/`compile` with a decoder (`atob`, `fromCharCode`, `b64decode`, `marshal.loads`, escapes) within a few lines of it | always (JS, TS, HTML, Python, Ruby, PHP) | — |
| `ENCODED-PAYLOAD` | An array of 32 or more hex, binary or byte literals | beside `EXEC-DECODED` | in a web script or Python, with or without code that turns numbers into text near it. Never in C, Rust, Swift, shaders, CSS, or paths that hold tables (`vector`, `fixture`, `wasm`, `shader`, `kernel`, `gpu`, `font`, `codec`, `table`, `lut`, `crc`, `sha`, `aes`, `dist`, `build`) |
| `STRING-DECODER` | `charCodeAt` and `fromCharCode` with XOR, shifts or modulo in one file | beside `EXEC-DECODED` | alone (hashing and base64 libraries look like this) |
| `ESCAPED-SOURCE` | A run of 30 or more `\x`/`\u` escapes | beside `eval` | alone; never in table paths |
| `PRIV-ESCALATION` | `curl … \| sh`, `sudo`, setuid bits, sudoers, `authorized_keys`, launch agents and daemons, cron, services, run keys, Gatekeeper and SIP off, quarantine stripped | in package.json and other manifests; in a JavaScript or Python file that itself runs commands (`child_process`, `subprocess`); in installed code: for `curl \| sh`, setuid, sudoers, launch daemons, SIP and Gatekeeper, quarantine, run keys | in shell scripts (installers use sudo), in tests, and for a bare `sudo`, a launch agent, cron or a service |
| `CREDENTIAL-ACCESS` | A JavaScript, Python or shell file that reads ssh keys, cloud and registry credentials, browser passwords and cookies, extension storage (wallet keys), the keychain, wallet files | in JavaScript or Python with network code in the same file, or in installed code | read only, in shell scripts, in tests |
| `WALLET-SIGNING` | `signTypedData`, `personal_sign`, `eth_sendTransaction`, `setApprovalForAll`, `increaseAllowance`, `signAllTransactions`, `permit`, … with a wallet provider in reach | with an unlimited allowance (`MaxUint256`), in obfuscated code, or in installed code (an extension or plugin asking your wallet to sign) | in the project's own code: that is what a dapp does |
| `THIRD-PARTY-SCRIPT` | `<script src="https://…">` without `integrity=` | over plain http, or on a project that asks wallets to sign (the supply-chain drainer: the script decides what gets signed) | otherwise |
| `RAW-IP` | `http://1.2.3.4`, `ws://…` to a bare address | beside another failing finding | alone |

The reasoning behind "out of place": a hex table in a Metal kernel, a CRC file or a CSS colour is the normal way to write it; the same bytes in a page's script next to `fromCharCode` are a payload. `sudo` in `install.sh` is how installers work; `sudo` in an npm `postinstall` is how a worm gets root. A dapp asks a wallet to sign; a dependency, a browser extension or an obfuscated bundle asking a wallet to approve an unlimited allowance is a drainer.

## Installed code

On a machine scan the same rules run over the directories of every VS Code-family editor's extensions, every agent harness's plugins, and every Chromium-family browser's extensions, as **installed** code: there, reading a credential store or asking a wallet to sign fails outright, because the project's own intent isn't a defence for code that arrived through a marketplace.

## The policy file

`--suspect-policy FILE` (default: the bundled, empty list) holds one entry per line: an id (`PRIV-ESCALATION` or `SUSPECT-PRIV-ESCALATION`) or `path:<text>` matched against the file's path inside the repo (`path:scripts/legacy/`). A finding that matches warns instead of failing and says so. There is no way to drop one: a reviewer should still see it.

## What it is not

A verdict. The rules find the shapes of attacks, including in honest code that happens to share one; they miss attacks written without them. Read what the finding points at. Built output (`dist`, `build`, `out`, `_site`, `.next`) is skipped in a repo and read as installed code elsewhere; minified bundles are read (a drainer ships minified), which is why `ENCODED-PAYLOAD` alone never fails and `EXEC-DECODED` needs the decoder beside the call.
