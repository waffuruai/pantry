"""Opt-in: is the developer's email in known breach data?

This is the one check that sends personal data off the machine, so it never
runs until the user says yes (asked once on a terminal, or `secure.py breach
--enable`), and the answer is remembered. Have I Been Pwned is used when
HIBP_API_KEY is set (its email lookup is paid); otherwise XposedOrNot's free
lookup. Results are cached for a week."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.parse

from . import net

WEEK = 7 * 86400


def consent(cache, ask: bool):
    """True/False once decided; None when undecided and we can't ask."""
    value = cache.get("breach_consent")
    if value in ("yes", "no"):
        return value == "yes"
    if not (ask and sys.stdin.isatty()):
        return None
    emails = ", ".join(emails_to_check()) or "your git email"
    reply = input(f"Check {emails} against breach data? This sends the address to "
                  f"{'Have I Been Pwned' if os.environ.get('HIBP_API_KEY') else 'XposedOrNot'}. [y/N] ")
    cache.set("breach_consent", "yes" if reply.strip().lower() in ("y", "yes") else "no")
    cache.conn.commit()
    return cache.get("breach_consent") == "yes"


def emails_to_check():
    found = []
    git = shutil.which("git")
    if git:
        found.append(subprocess.run([git, "config", "--global", "user.email"],
                                    capture_output=True, text=True).stdout.strip())
    gh = shutil.which("gh")
    if gh:
        p = subprocess.run([gh, "api", "user/emails", "--jq", ".[].email"], capture_output=True, text=True)
        if p.returncode != 0:
            p = subprocess.run([gh, "api", "user", "--jq", ".email // empty"], capture_output=True, text=True)
        found += p.stdout.split()
    seen, out = set(), []
    for e in found:
        e = e.strip().lower()
        if "@" in e and "noreply" not in e and e not in seen:
            seen.add(e)
            out.append(e)
    return out


def check(cache, offline=False):
    """{email: [breach name, ...]} for the emails that appear in breaches."""
    out = {}
    for email in emails_to_check():
        key = "breach:" + hashlib.sha256(email.encode()).hexdigest()
        run = cache.run(key)
        if run and (offline or run[1] > time.time() - WEEK):
            names = run[2]
        elif offline:
            continue
        else:
            try:
                names = _hibp(email) if os.environ.get("HIBP_API_KEY") else _xposedornot(email)
            except net.Offline:
                if not run:
                    continue
                names = run[2]
            else:
                cache.put_run(key, "", names)
        if names:
            out[email] = names
    cache.conn.commit()
    return out


def _hibp(email):
    status, body, _ = net.request(
        "https://haveibeenpwned.com/api/v3/breachedaccount/" + urllib.parse.quote(email),
        headers={"hibp-api-key": os.environ["HIBP_API_KEY"]})
    return [] if status == 404 else [b["Name"] for b in json.loads(body)]


def _xposedornot(email):
    status, body, _ = net.request("https://api.xposedornot.com/v1/check-email/" + urllib.parse.quote(email))
    if status == 404:
        return []
    data = json.loads(body)
    return [n for group in data.get("breaches", []) for n in group]
