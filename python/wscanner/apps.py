"""macOS apps and browsers, pending macOS updates, and Docker (the engine
and the images behind running containers)."""

from __future__ import annotations

import glob
import json
import os
import re
import shutil
from pathlib import Path

from .system import HOME, MACOS, Component, brew_casks, github, plist, run

BROWSERS = {
    "com.google.Chrome": "chrome", "org.mozilla.firefox": "firefox",
    "org.mozilla.firefoxdeveloperedition": "firefox-dev",
    "com.microsoft.edgemac": "edge", "com.brave.Browser": "brave",
    "company.thebrowser.Browser": "arc", "com.operasoftware.Opera": "opera",
    "com.vivaldi.Vivaldi": "vivaldi", "org.chromium.Chromium": "chromium",
}


def apps():
    """Every app in /Applications and ~/Applications (one folder deep), except
    Apple's own, which macOS updates cover."""
    if not MACOS:
        return []
    bundles = []
    for root in ("/Applications", os.path.join(HOME, "Applications")):
        bundles += glob.glob(os.path.join(root, "*.app")) + glob.glob(os.path.join(root, "*", "*.app"))
    out = []
    for b in sorted(set(bundles)):
        info = plist(os.path.join(b, "Contents", "Info.plist"))
        bid = info.get("CFBundleIdentifier", "")
        if not info or bid.startswith("com.apple."):
            continue
        ver = str(info.get("CFBundleShortVersionString") or info.get("CFBundleVersion") or "")
        c = Component("browser" if bid in BROWSERS else "app", os.path.basename(b)[:-4], ver, b,
                      extra={"bundle": os.path.basename(b), "id": bid})
        if bid in BROWSERS:
            c.extra["browser"] = BROWSERS[bid]
            c.extra["channel"] = _firefox_channel(b) if BROWSERS[bid] == "firefox" else ""
        electron = plist(os.path.join(b, "Contents", "Frameworks", "Electron Framework.framework",
                                      "Versions", "A", "Resources", "Info.plist"))
        if electron.get("CFBundleVersion"):
            c.extra["electron"] = str(electron["CFBundleVersion"])
        out.append(c)
    return out


def _firefox_channel(bundle):
    try:
        prefs = Path(bundle, "Contents", "Resources", "defaults", "pref", "channel-prefs.js").read_text()
    except OSError:
        return ""
    m = re.search(r'"app\.update\.channel",\s*"([^"]+)"', prefs)
    return m.group(1) if m else ""


def macos_updates():
    """[(title, version)] of recommended updates from the last automatic scan
    (no network), plus that scan's date."""
    if not MACOS:
        return [], ""
    out = run(["softwareupdate", "--list", "--no-scan"], timeout=60)
    found = re.findall(r"Title: ([^,]+), Version: ([^,]+),.*?Recommended: YES", out)
    last = run(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "LastSuccessfulDate"]).strip()
    return found, last


def docker():
    """The Docker engine and the containerd and runc it runs, from the daemon
    (nothing when it isn't running). Docker Desktop ships them inside its VM,
    so its update is the fix there."""
    exe = shutil.which("docker")
    if not exe:
        return []
    raw = run([exe, "version", "--format", "{{json .Server}}"], timeout=20).strip()
    try:
        server = json.loads(raw.splitlines()[-1])
    except (ValueError, IndexError):
        return []
    if not isinstance(server, dict):
        return []
    if MACOS or "Docker Desktop" in json.dumps(server):
        fix, auto = ("brew upgrade --cask docker-desktop", True) if "docker-desktop" in brew_casks() else (
            "Update Docker Desktop (Docker menu → Check for Updates)", False)
    else:
        fix, auto = "Upgrade the docker-ce, containerd.io and runc packages (sudo)", False
    found = [("docker engine", server.get("Version", ""), "moby/moby")]
    for comp in server.get("Components") or []:
        name = comp.get("Name", "").lower()
        if name in ("containerd", "runc"):
            found.append((name, comp.get("Version", ""),
                          "containerd/containerd" if name == "containerd" else "opencontainers/runc"))
    out = []
    for name, ver, repo in found:
        ver = ver.lstrip("v").split("-")[0]
        if re.fullmatch(r"\d+\.\d+\.\d+", ver):
            out.append(Component("tool", name, ver, exe, osv=("GIT", github(repo), f"v{ver}"), fix=fix, auto=auto))
    return out


def running_images():
    exe = shutil.which("docker")
    return sorted({r for r in run([exe, "ps", "--format", "{{.Image}}"], timeout=20).split() if r}) if exe else []


def image_id(ref: str) -> str:
    """The local image id for ref, or "" when it isn't pulled or built here."""
    exe = shutil.which("docker")
    out = run([exe, "image", "inspect", "--format", "{{.Id}}", ref], timeout=20).strip() if exe else ""
    return out if out.startswith("sha256:") else ""
