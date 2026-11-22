#!/usr/bin/env python3
"""Make a portable Pantry bundle with the scanner beside its desktop app."""

import argparse
import plistlib
import stat
import tomllib
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

DESKTOP = Path(__file__).resolve().parents[1]


def package(target, app, scanner, notices, output):
    ext = ".exe" if target.endswith("-windows-msvc") else ""
    entries = {
        "LICENSE.txt": (0o644, (DESKTOP / "LICENSE").read_bytes()),
        "PANTRY-SCANNER-NOTICES.txt": (
            0o644, (DESKTOP.parent / "rust/crates/wpantry-cli/THIRD-PARTY-NOTICES.txt").read_bytes()
        ),
        "PANTRY-DESKTOP-NOTICES.txt": (0o644, notices.read_bytes()),
        "FONT-LICENSE-GEIST.txt": (0o644, (DESKTOP / "fonts/LICENSE-Geist-OFL.txt").read_bytes()),
    }
    if target == "universal-apple-darwin":
        version = tomllib.loads((DESKTOP / "Cargo.toml").read_text())["package"]["version"]
        plist = {
            "CFBundleDevelopmentRegion": "en",
            "CFBundleDisplayName": "Pantry",
            "CFBundleExecutable": "Pantry",
            "CFBundleIdentifier": "ai.waffuru.pantry.desktop",
            "CFBundleIconFile": "Pantry.icns",
            "CFBundleName": "Pantry",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": version,
            "CFBundleVersion": version,
            "NSHighResolutionCapable": True,
        }
        entries["Pantry.app/Contents/Resources/Pantry.icns"] = (0o644, (DESKTOP / "assets/Pantry.icns").read_bytes())
        entries["Pantry.app/Contents/Info.plist"] = (0o644, plistlib.dumps(plist))
        entries["Pantry.app/Contents/MacOS/Pantry"] = (0o755, app.read_bytes())
        entries["Pantry.app/Contents/MacOS/wpantry"] = (0o755, scanner.read_bytes())
    else:
        entries[f"wpantry-desktop{ext}"] = (0o755, app.read_bytes())
        entries[f"wpantry{ext}"] = (0o755, scanner.read_bytes())

    write_zip(entries, output)


def write_zip(entries, output):
    with ZipFile(output, "w") as bundle:
        for name, (mode, body) in sorted(entries.items()):
            entry = ZipInfo(name)
            entry.create_system = 3  # Unix permissions for macOS and Linux.
            entry.external_attr = (stat.S_IFREG | mode) << 16
            bundle.writestr(entry, body, compress_type=ZIP_DEFLATED, compresslevel=9)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target")
    for arg in ("app", "scanner", "notices", "output"):
        parser.add_argument(arg, type=Path)
    package(**vars(parser.parse_args()))
