"""Small HTTP helpers. Every request names us and times out quickly; callers
decide what an offline machine means for their source."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request

from . import __version__

USER_AGENT = f"wscanner/{__version__} (+https://github.com/waffuruai/wscanner)"
TIMEOUT = 30


class Offline(Exception):
    """The source could not be reached."""


def request(url: str, data=None, headers=None, etag: str | None = None):
    """Returns (status, body bytes, etag). 304 when etag still matches."""
    h = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    h.update(headers or {})
    body = None
    if data is not None:
        body = json.dumps(data).encode()
        h["Content-Type"] = "application/json"
    if etag:
        h["If-None-Match"] = etag
    req = urllib.request.Request(url, data=body, headers=h)
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, r.read(), r.headers.get("ETag")
    except urllib.error.HTTPError as e:
        if e.code == 304:
            return 304, b"", etag
        if e.code == 404:
            return 404, e.read(), None
        raise Offline(f"{url}: HTTP {e.code}") from e
    except (urllib.error.URLError, OSError) as e:
        raise Offline(f"{url}: {e}") from e


def github_headers() -> dict:
    """GitHub API headers; a GITHUB_TOKEN, when set, lifts the anonymous
    rate limit (60 requests an hour)."""
    h = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        h["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    return h


def get_json(url: str, headers=None):
    status, body, _ = request(url, headers=headers)
    if status == 404:
        return None
    return json.loads(body)


def post_json(url: str, data):
    _, body, _ = request(url, data=data)
    return json.loads(body)
