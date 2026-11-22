#!/usr/bin/env python3
"""Check that the native Linux renderer maps a Pantry window under Xvfb."""

import argparse
import os
import subprocess
import tempfile
import time
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("app", type=Path)
parser.add_argument("scanner", type=Path)
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix="pantry-native-smoke-") as scratch:
    root = Path(scratch)
    env = dict(os.environ, HOME=scratch, WPANTRY_DB=str(root / "pantry.db"),
               WPANTRY_DESKTOP_HOME=scratch,
               XDG_STATE_HOME=str(root / "state"), XDG_CONFIG_HOME=str(root / "config"),
               LIBGL_ALWAYS_SOFTWARE="1")
    command = [args.app.resolve(), "--scanner", args.scanner.resolve()]
    process = subprocess.Popen(command, env=env)
    try:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            assert process.poll() is None, f"Pantry quit with status {process.returncode}."
            info = subprocess.run(["xwininfo", "-name", "Pantry"], capture_output=True, text=True, timeout=2)
            if info.returncode == 0 and "Map State: IsViewable" in info.stdout:
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("The Pantry window never became viewable.")
        subprocess.run(command, env=env, check=True, timeout=5)
        assert (root / "state" / "activate").read_bytes() == b"\n"
        assert process.poll() is None
    finally:
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=10)

print("Pantry opened one native Linux window and reused it on a second launch.")
