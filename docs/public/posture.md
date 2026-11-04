# The machine's own security settings

With the machine inventory, wpantry reads the settings that decide whether an exploit matters at all: is the disk encrypted, is the firewall on, is anything listening for remote logins, does the Mac log someone in without a password, do updates install on their own. Each is a read (`defaults read`, `launchctl print-disabled`, `fdesetup status`, a config file); nothing is changed. A failing Critical or High check fails the scan (exit 1), Medium and Low warn, and a check that can't tell says "couldn't tell" rather than pass.

Fixes marked *user* are settings of your own account; `wpantry fix` may apply them. Fixes marked *admin* need `sudo` or a System Settings pane and are printed for you.

`--no-posture` skips all of them; `--posture-policy FILE` lists ids to skip, one per line (`REMOTE-LOGIN` on a server that means to run ssh). The ids are the finding's `vuln_id` without `POSTURE-`.

The checks follow the CIS Apple macOS Benchmark and the CIS Distribution Independent Linux Benchmark. The projects they were written against are in the README's [acknowledgements](../../README.md#acknowledgements).

## macOS

| Id | CIS | Check | Severity | Fix |
|---|---|---|---|---|
| FILEVAULT | 2.6.1.1 | FileVault on | Critical | admin: System Settings → Privacy & Security → FileVault |
| FIREWALL | 2.2.1 | Application firewall on | Critical | admin: `socketfilterfw --setglobalstate on` |
| STEALTH | 2.2.2 | Firewall stealth mode | Medium | admin: `socketfilterfw --setstealthmode on` |
| GATEKEEPER | 2.6.5 | Gatekeeper on | High | admin: System Settings → Privacy & Security |
| SIP | 5.1.1 | System Integrity Protection on | Critical | admin: `csrutil enable` in Recovery |
| UPDATES-CHECK | 1.2 | Software Update checks and downloads | High | admin: `defaults write …SoftwareUpdate AutomaticCheckEnabled/AutomaticDownload` |
| UPDATES-INSTALL | 1.3 | Security responses and macOS updates install | High | admin: `…CriticalUpdateInstall`, `ConfigDataInstall`, `AutomaticallyInstallMacOSUpdates` |
| APPSTORE-UPDATES | 1.4 | App Store updates install | Medium | admin: `…com.apple.commerce AutoUpdate` |
| REMOTE-LOGIN | 2.3.3.4 | Remote Login (ssh) off | Critical | admin: Sharing → Remote Login |
| SCREEN-SHARING | 2.3.3.1 | Screen Sharing off | High | admin: Sharing |
| REMOTE-MANAGEMENT | 2.3.3.5 | Remote Management off | High | admin: Sharing |
| FILE-SHARING | 2.3.3.2 | File Sharing off | High | admin: Sharing |
| REMOTE-EVENTS | 2.3.3.6 | Remote Apple Events off | Medium | admin: `systemsetup -setremoteappleevents off` |
| INTERNET-SHARING | 2.3.3.7 | Internet Sharing off | High | admin: Sharing |
| PRINTER-SHARING | 2.3.3.3 | Printer Sharing off | Low | admin: `cupsctl --no-share-printers` |
| GUEST | 2.13.1 | Guest account disabled | High | admin: `defaults write …loginwindow GuestEnabled -bool false` |
| AUTO-LOGIN | 2.13.3 | Automatic login off | Critical | admin: Users & Groups |
| PASSWORD-HINTS | 2.11.5 | Password hints off | Medium | admin: `…loginwindow RetriesUntilHint -int 0` |
| SCREEN-LOCK | 2.11.2 | Password required after sleep | High | user: Lock Screen settings |
| SCREENSAVER | 2.11.1 | Screen saver within 20 minutes | Medium | user: `defaults -currentHost write com.apple.screensaver idleTime -int 1200` |
| TERMINAL-SECURE-INPUT | 6.4.1 | Terminal Secure Keyboard Entry | Medium | user: `defaults write com.apple.Terminal SecureKeyboardEntry -bool true` |
| SAFARI-SAFE-FILES | 6.3.1 | Safari doesn't open downloads | Medium | user: Safari → Settings → General |
| BLUETOOTH-SHARING | 2.3.3.10 | Bluetooth Sharing off | Low | user: `defaults -currentHost write com.apple.Bluetooth PrefKeyServicesEnabled -bool false` |
| XPROTECT | 5.10 | XProtect data under 45 days old, and XProtect Remediator present; the evidence names both versions (`xprotect version` on macOS 15 and later, else the bundles' `CFBundleShortVersionString`) | Medium | admin: `softwareupdate --background-critical` |
| SECURE-BOOT | | Secure Boot at Full Security: `bputil -d` as root, else `system_profiler SPiBridgeDataType` (Apple silicon and T2). Reduced or Medium Security warns (a third-party kext may need it), Permissive or none fails; an Intel Mac without a T2 has no policy and says so | High | admin: Startup Security Utility in Recovery |
| NOT-ADMIN | | The everyday account is a standard user (`id -Gn` without `admin`), so what it runs can't install system-wide or change settings without another account's password | Medium | admin: a separate administrator account, then take admin away from the everyday one |
| TIME-SYNC | 2.3.2.1 | Time and date set automatically (`systemsetup -getusingnetworktime`, directly or through `sudo -n`; without admin, manual with the time server `/etc/ntp.conf` names) | Medium | admin: `systemsetup -setusingnetworktime on` |
| AIRDROP | 2.3.1.1 | AirDrop disabled, off, or contacts only (`com.apple.sharingd DiscoverableMode`); Everyone warns | Medium | user: `defaults write com.apple.sharingd DiscoverableMode -string "Contacts Only"` |
| FIREWALL-LOGGING | 3.6 | Firewall logging on: `socketfilterfw --getloggingmode` before macOS 15, a configuration profile's `com.apple.security.firewall EnableLogging` since (manual when there is none, as there is no other switch) | Low | admin: a configuration profile (or `socketfilterfw --setloggingmode on` before macOS 15) |
| DNS-ENCRYPTED | | DNS leaves the Mac encrypted: a DoH or DoT configuration profile or a DNS proxy extension (NextDNS, AdGuard, Cloudflare) in the network-extension settings, or a local stub that forwards encrypted (dnscrypt-proxy, stubby, cloudflared, unbound with `forward-tls-upstream`) as the resolver `scutil --dns` names. A VPN tunnel or Tailscale's resolver is "couldn't tell"; plain addresses on UDP 53 warn | Medium | admin: a DoH/DoT profile (NextDNS, Cloudflare, Quad9, AdGuard, Control D publish them) or the provider's app, or a local stub |
| LOCKDOWN | 2.6.7 | Lockdown Mode (advisory) | Low | for people at risk of targeted attacks |

## Developer tools (every OS)

| Id | Check | Severity | Fix |
|---|---|---|---|
| EXTENSION-COOLDOWN | Every VS Code-family editor (Code, Insiders, Cursor, Windsurf, VSCodium, Positron) has `extensions.installCooldownHours` of 24 or more, so a freshly published (possibly compromised) extension version is never installed here before the marketplace has had time to pull it | High | user: `wpantry harden extension-cooldown --hours 72` (edits each editor's settings.json in place; `--fix` runs it) |
| GIT-HOOKS | A global `core.hooksPath` with a `pre-commit` hook, so a secret is stopped at the commit | Low | ops: `mise run hooks`; elsewhere point `git config --global core.hooksPath` at a directory with a gitleaks pre-commit |

An editor with `extensions.autoUpdate: false` is reported as "updates by hand" (a warning): manual updates keep a bad version from arriving on its own, and the cooldown still stops it being installed by hand on the day it appears.

## Linux

| Id | CIS | Check | Severity | Fix |
|---|---|---|---|---|
| DISK-ENCRYPTION | 1.4 | A LUKS volume in use | Critical | admin: encrypt at install |
| FIREWALL | 3.5 | ufw, firewalld, nftables or iptables filtering input | High | admin: `ufw enable` |
| AUTO-UPDATES | 1.9 | unattended-upgrades or dnf-automatic | High | admin |
| SSH-ROOT | 5.2.8 | `PermitRootLogin no` (when sshd runs) | High | admin |
| SSH-PASSWORDS | 5.2.10 | `PasswordAuthentication no` (when sshd runs) | High | admin |
| AUTO-LOGIN | 1.8 | No display-manager automatic login | Critical | admin |
| MAC | 1.6 | AppArmor or SELinux enforcing | Medium | admin |
| SUDO-NOPASSWD | 5.3 | sudo asks for a password | Medium | admin: visudo |
| PATH-WRITABLE | 6.2 | No world-writable directory on PATH | Medium | admin: `chmod o-w` |
| TIME-SYNC | 2.1.1 | Clock synchronised | Low | admin: `timedatectl set-ntp true` |
| KERNEL-TCP-IP-OPTIONS | | Running kernel outside [CVE-2026-98432](https://osv.dev/vulnerability/CVE-2026-98432)'s affected range (upstream fixes 5.10.272, 5.15.223, 6.1.190, 6.6.159, 6.12.113, 6.18.56, 7.2.10), or an nftables/iptables rule dropping inbound TCP with IP options (`ip hdrlength > 5`). A distro kernel with a backport under its own numbering passes only through the rule: check the vendor's advisory. The ruleset is read as root or through `sudo -n` (never a prompt); manual when neither works | Critical | admin: the nft stopgap (`wpantry mitigate CVE-2026-98432`), then the kernel update |
| MPTCP | | `net.mptcp.enabled = 0` (or MPTCP not built) and no program still holds an MPTCP listening socket: the sysctl only stops new sockets, a service listening since before it flipped keeps MPTCP until restarted. Listeners come from `ss -tlnpi` as root or through `sudo -n` (the `tcp-ulp-mptcp` mark, no kernel module needed), else from `ss -Mlnp` where the kernel has `mptcp_diag`; without either the check can't see them and says so (manual). Only the host network namespace: a container's own listeners are judged by the repo check | Medium | admin: `sysctl -w net.mptcp.enabled=0`, then `systemctl restart` of the services the evidence names (`wpantry mitigate CVE-2026-98432` does the first and prints the second) |
| DNS-ENCRYPTED | | DNS leaves the machine encrypted: systemd-resolved with `DNSOverTLS=yes` (`resolvectl status`, else `resolved.conf`), NetworkManager `ipv4.dns-over-tls yes` on an active connection, or a local stub that forwards encrypted (stubby, dnscrypt-proxy, cloudflared, nextdns, AdGuard Home, unbound with `forward-tls-upstream: yes`) as the nameserver in `/etc/resolv.conf`. `opportunistic` warns (it can be downgraded); resolved's stub without DoT, or plain addresses on UDP 53, warn; a stub it can't judge is "couldn't tell" | Medium | admin: `DNSOverTLS=yes` and `DNS=1.1.1.1#cloudflare-dns.com` in `resolved.conf`, `nmcli connection modify <name> ipv4.dns-over-tls yes`, or a local stub |

The DNS check is Medium on purpose: an internal resolver (Kubernetes, Docker, a corporate split-DNS server on the LAN or over the VPN) legitimately answers in plain DNS, so a plaintext resolver is a warning that says where the queries go, never a failure. It passes on evidence of encryption (a profile, a proxy extension, resolved's DoT, a known stub), says "couldn't tell" for a VPN tunnel, Tailscale's resolver or a stub it doesn't know, and warns for plain addresses on UDP 53, which an ISP or a hotspot can read and rewrite.

The kernel check is the pattern for a vulnerability with no fix to install yet: the check knows the affected versions and the stopgap, passes on either, and tells you which one you are relying on. [usage.md](usage.md#exposed-with-no-fix-yet) covers `wpantry watch`, which asks OSV again about such advisories.

Not covered yet: Windows (#11), Time Machine encryption, sudo timeouts (need root to read), audit logging.

## Persistence

With the machine inventory, and whatever `--no-posture` says, wpantry lists every place a program can arrange to run again and compares the list with the last scan's (kind `persistence`). An infostealer or a backdoor has to survive a reboot, and the places it can do that from are few:

- **macOS:** launch agents and daemons (`~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`, every program, with the `EnvironmentVariables` they set), the login items and launch agents and daemons apps carry in their bundles for ServiceManagement to register (`Contents/Library/LoginItems`, `LaunchAgents` and `LaunchDaemons` of every app in `/Applications` and `~/Applications`; whether each is enabled lives in Background Task Management, whose only reader, `sfltool dumpbtm`, asks for an administrator's password, so wpantry doesn't run it), the user's crontab and `/etc/crontab`, pending `at` jobs, periodic scripts and local files, emond rules and clients, authorization plugins (`/Library/Security/SecurityAgentPlugins`), third-party kernel extensions (`/Library/Extensions`), system extensions (`systemextensionsctl list`), Quick Look generators and Spotlight importers (yours and the system's), the shells' startup files (`~/.zshrc`, `~/.bash_profile`, `/etc/zshrc` and the rest), and `launchctl getenv DYLD_INSERT_LIBRARIES`.
- **Linux:** systemd units (yours in `~/.config/systemd/user`, the system's in `/etc/systemd` and `/usr/local/lib/systemd`; the distribution's own in `/lib/systemd` are packaged and left out), crontabs, `/etc/cron.d` and the `cron.hourly` to `cron.monthly` scripts, `at` jobs, XDG autostart entries, the startup files with `/etc/profile.d` and `/etc/environment`, and `/etc/ld.so.preload`.

Each persisted program is put to `codesign -dv` and `codesign --verify --strict` on macOS (Apple, a developer identity, the App Store, ad hoc, unsigned, or a signature that no longer verifies) and asked for its `com.apple.quarantine` attribute (still there: downloaded and not yet cleared by Gatekeeper; missing from a downloaded program: someone stripped it). Both go in the finding's note.

| Id | When | Status |
|---|---|---|
| PERSISTENCE-NEW | An item the last scan that read its source didn't see: a new plist, a login item, a cron line, a plugin, an existing launch agent that now runs something else. The startup files are compared by line; the note gives the line numbers, never the text (a line can hold a token) | warn |
| PERSISTENCE-INJECTION | An item that sets `DYLD_INSERT_LIBRARIES`, `LD_PRELOAD` or `LD_AUDIT`, or a library in `/etc/ld.so.preload`: every program it starts loads that library first | warn, every scan |
| PERSISTENCE-SIGNATURE | A persisted program whose code signature doesn't verify: it changed after it was signed | warn, every scan |
| PERSISTENCE-HIDDEN | A persisted program in a temporary or hidden place (`/tmp`, `/var/folders`, `/Users/Shared`, a dot-directory in your home that isn't a known tool's) | warn, every scan |

The first scan records the list (the cache's `persistence` table, as hashes and locations; the counts say how many were recorded) and reports nothing new. Each source keeps its own record, so one that couldn't be read once (reported as not checked) doesn't make everything in it new the next time; an item that goes and comes back is new again. Anything you add yourself warns once and is in the record from then on. The list of persisted programs is also what the malware scan reads.
