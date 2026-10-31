# The machine's own security settings

With the machine inventory, wpantry reads the settings that decide whether an exploit matters at all: is the disk encrypted, is the firewall on, is anything listening for remote logins, does the Mac log someone in without a password, do updates install on their own. Each is a read (`defaults read`, `launchctl print-disabled`, `fdesetup status`, a config file); nothing is changed. A failing Critical or High check fails the scan (exit 1), Medium and Low warn, and a check that can't tell says "couldn't tell" rather than pass.

Fixes marked *user* are settings of your own account; `wpantry --update` may apply them. Fixes marked *admin* need `sudo` or a System Settings pane and are printed for you.

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
| XPROTECT | 5.10 | XProtect data under 45 days old | Medium | admin: `softwareupdate --background-critical` |
| LOCKDOWN | 2.6.7 | Lockdown Mode (advisory) | Low | for people at risk of targeted attacks |

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

Not covered yet: Windows (#11), Time Machine encryption, sudo timeouts (need root to read), audit logging.
