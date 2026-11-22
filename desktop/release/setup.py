#!/usr/bin/env python3
"""Build the compressed payload and the platform download for Pantry Setup."""

import argparse
import gzip
import io
import plistlib
import shutil
import struct
import tarfile
import tomllib
import zlib
from pathlib import Path
from zipfile import ZipFile

from package import DESKTOP, write_zip


def payload(source, output):
    records = []
    with ZipFile(source) as archive:
        for item in archive.infolist():
            path = item.filename.encode("utf-8")
            body = archive.read(item)
            executable = bool((item.external_attr >> 16) & 0o111)
            records.extend((struct.pack("<HIB", len(path), len(body), executable), path, body))
    output.write_bytes(zlib.compress(b"".join(records), level=9))


def bundle(target, setup, data, output):
    if target.endswith("-windows-msvc"):
        shutil.copyfile(setup, output)
    elif target == "universal-apple-darwin":
        version = tomllib.loads((DESKTOP / "Cargo.toml").read_text())["package"]["version"]
        plist = {
            "CFBundleDisplayName": "Pantry Setup",
            "CFBundleExecutable": "Pantry Setup",
            "CFBundleIdentifier": "ai.waffuru.pantry.setup",
            "CFBundleIconFile": "Pantry.icns",
            "CFBundleName": "Pantry Setup",
            "CFBundlePackageType": "APPL",
            "CFBundleShortVersionString": version,
            "CFBundleVersion": version,
            # Agent app: Setup installs and hands off to Pantry.app, so it never
            # takes a Dock slot. osascript error alerts still show.
            "LSUIElement": True,
        }
        write_zip({
            "Pantry Setup.app/Contents/Info.plist": (0o644, plistlib.dumps(plist)),
            "Pantry Setup.app/Contents/MacOS/Pantry Setup": (0o755, setup.read_bytes()),
            "Pantry Setup.app/Contents/Resources/Pantry.icns": (0o644, (DESKTOP / "assets/Pantry.icns").read_bytes()),
            "Pantry Setup.app/Contents/Resources/pantry-setup.zlib": (0o644, data.read_bytes()),
        }, output)
    else:
        write_tar({
            "Pantry Setup": (0o755, setup.read_bytes()),
            "pantry-setup.desktop": (0o755, LINUX_LAUNCHER.encode()),
            "README.txt": (0o644, LINUX_README.encode()),
        }, output)


# Double-clicking a bare ELF does nothing in most Linux file managers, so the
# download carries a desktop entry that runs Setup from the folder it sits in.
# %k is the entry's own path; field codes may not appear inside quotes, so it
# reaches sh as $0. After the string-value escapes (\\ to \) the Exec rules
# give sh the script: exec "$(dirname "$0")/Pantry Setup"
LINUX_LAUNCHER = """[Desktop Entry]
Type=Application
Version=1.0
Name=Pantry Setup
Comment=Install or update Pantry for this account
Exec=sh -c "exec \\\\"\\\\$(dirname \\\\"\\\\$0\\\\")/Pantry Setup\\\\"" %k
Icon=system-software-install
Terminal=false
Categories=Utility;
"""

LINUX_README = """Pantry Setup installs Pantry for this account and adds it to the app menu.

Open "pantry-setup.desktop" (GNOME Files: right-click, Allow Launching, then
open it), or run Setup from a terminal in this folder:

    ./"Pantry Setup"

If the files lost their permissions while extracting, run this first:

    chmod +x "Pantry Setup" pantry-setup.desktop

To remove Pantry later: ./"Pantry Setup" --uninstall
"""


def write_tar(entries, output):
    """Write a gzipped tar that depends only on its entries: sorted names,
    fixed modes, owner 0, mtime 0 in both the tar and gzip headers."""
    with output.open("wb") as stream, gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.GNU_FORMAT) as archive:
            for name, (mode, body) in sorted(entries.items()):
                entry = tarfile.TarInfo(name)
                entry.size = len(body)
                entry.mode = mode
                entry.mtime = 0
                entry.uid = entry.gid = 0
                entry.uname = entry.gname = ""
                archive.addfile(entry, io.BytesIO(body))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(required=True, dest="command")
    prepare = commands.add_parser("payload")
    prepare.add_argument("source", type=Path)
    prepare.add_argument("output", type=Path)
    pack = commands.add_parser("bundle")
    pack.add_argument("target")
    pack.add_argument("setup", type=Path)
    pack.add_argument("data", type=Path)
    pack.add_argument("output", type=Path)
    args = vars(parser.parse_args())
    operation = args.pop("command")
    (payload if operation == "payload" else bundle)(**args)
