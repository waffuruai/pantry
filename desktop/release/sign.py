#!/usr/bin/env python3
"""Sign the app bundles inside a Pantry release ZIP, or a Windows .exe.

    sign.py macos ZIP [--identity NAME --keychain PATH] [--notary-profile NAME]
    sign.py windows FILE --thumbprint SHA1 [--timestamp-url URL]

macOS: every Mach-O under Contents/MacOS is signed first, then the bundle,
each with a fixed identifier and the hardened runtime, so Info.plist is bound
to the signature and the identity stays the same from version to version.
The default identity "-" is an ad-hoc signature: no certificate, no
timestamp, and the same bytes for the same input. With a Developer ID
identity the signature carries a secure timestamp, so two runs differ; with
--notary-profile the ZIP is notarized and the ticket stapled to each app.

Windows: Authenticode with a certificate already in the user's store,
selected by thumbprint. For a ZIP, every .exe inside is signed.

The ZIP is rewritten in place with the same deterministic layout as
package.py (sorted names, fixed modes, no timestamps).

Example (the release workflow runs this after the two-build compare):

    python3 desktop/release/sign.py macos dist/wpantry-desktop-universal-apple-darwin.zip
"""

import argparse
import glob
import json
import os
import subprocess
import tempfile
from pathlib import Path
from zipfile import ZipFile

from package import write_zip

# Bundle name -> (bundle identifier, identifier for nested executables).
IDENTIFIERS = {
    "Pantry.app": ("ai.waffuru.pantry.desktop", "ai.waffuru.pantry.scanner"),
    "Pantry Setup.app": ("ai.waffuru.pantry.setup", None),
}


def extract(archive, root):
    """Unpack a ZIP and return {name: mode} for every file in it."""
    modes = {}
    with ZipFile(archive) as bundle:
        for item in bundle.infolist():
            if item.is_dir():
                continue
            # Refuse anything that would land outside root.
            target = (root / item.filename).resolve()
            if root.resolve() not in target.parents:
                raise SystemExit(f"{archive}: unsafe path {item.filename!r}")
            bundle.extract(item, root)
            modes[item.filename] = (item.external_attr >> 16) & 0o777 or 0o644
            target.chmod(modes[item.filename])
    return modes


def rezip(root, modes, archive):
    entries = {}
    for path in sorted(p for p in root.rglob("*") if p.is_file()):
        name = path.relative_to(root).as_posix()
        # New files (the signature, a stapled ticket) are plain data.
        entries[name] = (modes.get(name, 0o644), path.read_bytes())
    write_zip(entries, archive)


def codesign(path, identifier, identity, keychain):
    command = ["codesign", "--force", "--sign", identity, "--identifier", identifier, "--options", "runtime"]
    if identity != "-":
        command.append("--timestamp")
    if keychain:
        command.extend(["--keychain", keychain])
    subprocess.run([*command, str(path)], check=True)


def notarize(archive, profile, keychain):
    command = ["xcrun", "notarytool", "submit", str(archive), "--keychain-profile", profile,
               "--wait", "--output-format", "json"]
    if keychain:
        command.extend(["--keychain", keychain])
    result = json.loads(subprocess.run(command, check=True, capture_output=True, text=True).stdout)
    if result.get("status") != "Accepted":
        raise SystemExit(f"notarization of {archive.name} ended as {result.get('status')}: run "
                         f"`xcrun notarytool log {result.get('id')}` for the reasons")


def macos(archive, identity, keychain, notary_profile):
    with tempfile.TemporaryDirectory(prefix="pantry-sign-") as temp:
        root = Path(temp)
        modes = extract(archive, root)
        apps = sorted(p for p in root.iterdir() if p.suffix == ".app")
        if not apps:
            raise SystemExit(f"{archive}: no .app bundle to sign")
        for app in apps:
            if app.name not in IDENTIFIERS:
                raise SystemExit(f"{archive}: no identifier for {app.name}")
            bundle_id, nested_id = IDENTIFIERS[app.name]
            main = app / "Contents/MacOS" / app.stem
            # Inside out: nested executables, then the bundle (which signs
            # the main executable and seals Info.plist and Resources).
            for nested in sorted((app / "Contents/MacOS").iterdir()):
                if nested != main:
                    codesign(nested, nested_id or bundle_id, identity, keychain)
            codesign(app, bundle_id, identity, keychain)
            subprocess.run(["codesign", "--verify", "--deep", "--strict", str(app)], check=True)
        rezip(root, modes, archive)
        if notary_profile:
            notarize(archive, notary_profile, keychain)
            for app in apps:
                subprocess.run(["xcrun", "stapler", "staple", str(app)], check=True)
                subprocess.run(["xcrun", "stapler", "validate", str(app)], check=True)
            rezip(root, modes, archive)


def signtool():
    found = sorted(glob.glob(r"C:\Program Files (x86)\Windows Kits\10\bin\10.*\x64\signtool.exe"))
    if not found:
        raise SystemExit("signtool.exe not found in the Windows SDK")
    return found[-1]


def authenticode(files, thumbprint, timestamp_url):
    tool = signtool()
    paths = [str(f) for f in files]
    subprocess.run([tool, "sign", "/sha1", thumbprint, "/fd", "SHA256", "/tr", timestamp_url, "/td", "SHA256",
                    *paths], check=True)
    subprocess.run([tool, "verify", "/pa", *paths], check=True)


def windows(target, thumbprint, timestamp_url):
    if target.suffix.lower() == ".exe":
        authenticode([target], thumbprint, timestamp_url)
        return
    with tempfile.TemporaryDirectory(prefix="pantry-sign-") as temp:
        root = Path(temp)
        modes = extract(target, root)
        executables = sorted(root.rglob("*.exe"))
        if not executables:
            raise SystemExit(f"{target}: no .exe to sign")
        authenticode(executables, thumbprint, timestamp_url)
        rezip(root, modes, target)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    platforms = parser.add_subparsers(required=True, dest="platform")
    mac = platforms.add_parser("macos")
    mac.add_argument("archive", type=Path)
    mac.add_argument("--identity", default="-")
    mac.add_argument("--keychain")
    mac.add_argument("--notary-profile")
    win = platforms.add_parser("windows")
    win.add_argument("target", type=Path)
    win.add_argument("--thumbprint", default=os.environ.get("WINDOWS_CERT_THUMBPRINT"))
    win.add_argument("--timestamp-url", default="http://timestamp.digicert.com")
    args = parser.parse_args()
    if args.platform == "macos":
        macos(args.archive, args.identity, args.keychain, args.notary_profile)
    else:
        if not args.thumbprint:
            parser.error("windows signing needs --thumbprint or WINDOWS_CERT_THUMBPRINT")
        windows(args.target, args.thumbprint, args.timestamp_url)
