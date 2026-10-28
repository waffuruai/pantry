"""Side feeds: CISA KEV, endoflife.date, the Homebrew cask catalog, the
Chrome and Firefox release feeds, PostgreSQL's security table, the Arch
tracker and GitHub's latest releases. Each is cached and refetched only when stale (with an ETag where the
server supports one). A feed that can't be reached and has nothing cached
raises net.Offline, so the caller reports it unchecked instead of clean."""

from __future__ import annotations

import datetime as dt
import html
import json
import re

from . import net

DAY = 86400
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CASKS_URL = "https://formulae.brew.sh/api/cask.json"
CHROME_URL = ("https://versionhistory.googleapis.com/v1/chrome/platforms/{}/channels/stable"
              "/versions/all/releases?filter=endtime=none")
FIREFOX = "https://product-details.mozilla.org/1.0/"
POSTGRES_URL = "https://www.postgresql.org/support/security/"
ARCH_URL = "https://security.archlinux.org/issues/all.json"
VSCODE_LISTS = "https://main.vscode-cdn.net/extensions/marketplace.json"
MARKETPLACE = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
OPENVSX = "https://open-vsx.org/api/{}/{}/latest"
GITHUB_LATEST = "https://api.github.com/repos/{}/releases/latest"


def _etag_fetch(cache, url, key, max_age, offline):
    """Body bytes when a refetch returned new data, else None."""
    if offline or cache.fresh(f"{key}_at", max_age):
        return None
    try:
        status, body, etag = net.request(url, etag=cache.get(f"{key}_etag"))
    except net.Offline:
        return None
    cache.touch(f"{key}_at")
    if status != 200:
        return None
    if etag:
        cache.set(f"{key}_etag", etag)
    return body


def kev(cache, offline=False):
    body = _etag_fetch(cache, KEV_URL, "kev", DAY, offline)
    if body:
        rows = [(v["cveID"], v.get("dateAdded", ""), v.get("vulnerabilityName", ""))
                for v in json.loads(body).get("vulnerabilities", [])]
        cache.conn.execute("DELETE FROM kev")
        cache.conn.executemany("INSERT OR REPLACE INTO kev VALUES (?, ?, ?)", rows)
        cache.conn.commit()
    ids = cache.kev_ids()
    if not ids:
        raise net.Offline("CISA KEV list unreachable and not cached")
    return ids


def eol(cache, product, version, cycle, offline=False):
    """(cycle, eol date or None, latest in cycle, still supported cycles) for
    `version`, or None when endoflife.date doesn't know the product or cycle."""
    if not (offline or cache.fresh(f"eol_at:{product}", 7 * DAY)):
        try:
            data = net.get_json(f"https://endoflife.date/api/{product}.json") or []
            cache.conn.execute("DELETE FROM eol WHERE product = ?", (product,))
            cache.conn.executemany("INSERT OR REPLACE INTO eol VALUES (?, ?, ?, ?)", [
                (product, str(c["cycle"]), json.dumps(c.get("eol")), str(c.get("latest", "")))
                for c in data])
            cache.touch(f"eol_at:{product}")
        except net.Offline:
            pass
    rows = cache.conn.execute("SELECT cycle, eol, latest FROM eol WHERE product = ?", (product,)).fetchall()
    if not rows:
        raise net.Offline(f"endoflife.date ({product}) unreachable and not cached")
    supported = [c for c, e, _ in rows if not _past(json.loads(e))]
    for c, e, latest in rows:
        if c == cycle:
            end = json.loads(e)
            return c, (end if _past(end) else None), latest, supported
    return None


def _past(end) -> bool:
    if end is True:
        return True
    if isinstance(end, str):
        try:
            return dt.date.fromisoformat(end) <= dt.date.today()
        except ValueError:
            return False
    return False


def casks(cache, offline=False):
    """{app bundle name: (cask token, latest version)} from the public cask
    catalog, refreshed weekly."""
    body = _etag_fetch(cache, CASKS_URL, "casks", 7 * DAY, offline)
    if body:
        rows = {}
        for c in json.loads(body):
            version = str(c.get("version") or "")
            if not version or version == "latest":
                continue
            for art in c.get("artifacts") or []:
                for app in (art.get("app") or []) if isinstance(art, dict) else []:
                    if isinstance(app, str) and app.endswith(".app"):
                        rows.setdefault(app, (c["token"], version.split(",")[0]))
        cache.conn.execute("DELETE FROM casks")
        cache.conn.executemany("INSERT INTO casks VALUES (?, ?, ?)",
                               [(a, t, v) for a, (t, v) in rows.items()])
        cache.conn.commit()
    out = {a: (t, v) for a, t, v in cache.conn.execute("SELECT app, token, version FROM casks")}
    if not out:
        raise net.Offline("the Homebrew cask catalog is unreachable and not cached")
    return out


def chrome(cache, platform, offline=False):
    """[(version, serving since epoch)] currently served on the stable channel."""
    def fetch():
        out = []
        for r in (net.get_json(CHROME_URL.format(platform)) or {}).get("releases", []):
            start = (r.get("serving") or {}).get("startTime", "")
            out.append((r["version"], _epoch(start)))
        return out
    return cache.memo(f"chrome:{platform}", fetch, offline=offline)


def firefox(cache, offline=False):
    """{"latest", "esr": [...], "dates": {version: epoch}}."""
    def fetch():
        v = net.get_json(FIREFOX + "firefox_versions.json") or {}
        dates = {}
        for name in ("firefox_history_major_releases.json", "firefox_history_stability_releases.json"):
            for ver, day in (net.get_json(FIREFOX + name) or {}).items():
                dates[ver] = _epoch(day)
        esr = [v[k].replace("esr", "") for k in v if k.startswith("FIREFOX_ESR") and v[k]]
        return {"latest": v.get("LATEST_FIREFOX_VERSION", ""), "esr": esr, "dates": dates}
    return cache.memo("firefox", fetch, offline=offline)


def github_latest(cache, repo, offline=False):
    """The version of `repo`'s latest GitHub release (its tag without a
    leading v), refreshed daily."""
    def fetch():
        tag = (net.get_json(GITHUB_LATEST.format(repo), headers=net.github_headers()) or {}).get("tag_name", "")
        if not tag:
            raise net.Offline(f"{repo} has no latest release")
        return re.sub(r"^v(?=\d)", "", tag)
    return cache.memo(f"github-latest:{repo}", fetch, offline=offline)


def postgres(cache, offline=False):
    """The PostgreSQL project's own security table (OSV has no PostgreSQL
    release data) for every supported major. Older majors already fail end
    of life."""
    def fetch():
        _, body, _ = net.request(POSTGRES_URL, headers={"Accept": "text/html"})
        return parse_postgres(body.decode("utf-8", "replace"))
    return cache.memo("postgres", fetch, offline=offline)


def parse_postgres(page: str):
    """[{cve, majors, fixed, component, score, vector, summary}] from the
    table at postgresql.org/support/security/."""
    out = []
    for row in re.findall(r"<tr>(.*?)</tr>", page, re.S):
        cells = [html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", c))).strip()
                 for c in re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)]
        if len(cells) < 5 or not re.match(r"CVE-\d{4}-\d+", cells[0]):
            continue
        meta = re.match(r"(.*?)\s+([\d.]+)\s+(AV:\S+)?", cells[3])
        out.append({
            "cve": cells[0].split()[0],
            "majors": [m.strip() for m in cells[1].split(",") if m.strip()],
            "fixed": [f.strip() for f in cells[2].split(",") if f.strip()],
            "component": meta.group(1) if meta else cells[3],
            "score": float(meta.group(2)) if meta else 0.0,
            "vector": (meta.group(3) or "") if meta else "",
            "summary": re.sub(r"\s*more details$", "", cells[4]),
        })
    return out


def arch(cache, offline=False):
    """The Arch Linux security tracker's advisory groups:
    [{name, packages, status, severity, affected, fixed, issues}]."""
    def fetch():
        groups = net.get_json(ARCH_URL)
        if not groups:
            raise net.Offline("the Arch security tracker returned nothing")
        return groups
    return cache.memo("arch-tracker", fetch, offline=offline)


def vscode_lists(cache, offline=False):
    """{"malicious": set, "deprecated": {id: replacement or ""}}: the lists VS
    Code itself downloads. Extension ids are lowercased."""
    data = cache.memo("vscode-lists", lambda: net.get_json(VSCODE_LISTS) or {}, offline=offline)
    deprecated = {}
    for ext, info in (data.get("deprecated") or {}).items():
        repl = ""
        if isinstance(info, dict):
            repl = ((info.get("extension") or {}).get("id") or info.get("additionalInfo") or "") if info else ""
        deprecated[ext.lower()] = repl if isinstance(repl, str) else ""
    return {"malicious": {m.lower() for m in data.get("malicious", [])}, "deprecated": deprecated}


def latest_extensions(cache, ids, openvsx: bool, offline=False):
    """{id: latest version} from Microsoft's marketplace, or Open VSX (which
    Cursor, Windsurf and VSCodium install from). Unknown ids are left out."""
    ids = sorted(set(ids))
    key = f"{'openvsx' if openvsx else 'marketplace'}:{','.join(ids)}"

    def fetch():
        out = {}
        if openvsx:
            for i in ids:
                ns, _, name = i.partition(".")
                d = net.get_json(OPENVSX.format(ns, name))
                if d and d.get("version"):
                    out[i] = d["version"]
            return out
        for n in range(0, len(ids), 100):
            body = {"filters": [{"criteria": [{"filterType": 7, "value": i} for i in ids[n:n + 100]],
                                 "pageSize": 100}], "flags": 1 | 16}  # versions, with properties
            _, raw, _ = net.request(MARKETPLACE, data=body,
                                    headers={"Accept": "application/json;api-version=7.2-preview.1"})
            for e in json.loads(raw)["results"][0].get("extensions", []):
                ext = f"{e['publisher']['publisherName']}.{e['extensionName']}".lower()
                stable = [v["version"] for v in e.get("versions", [])
                          if not any(p.get("key") == "Microsoft.VisualStudio.Code.PreRelease"
                                     for p in v.get("properties") or [])]
                if stable or e.get("versions"):
                    out[ext] = (stable or [e["versions"][0]["version"]])[0]
        return out
    return cache.memo(key, fetch, offline=offline)


def severity_from_score(score: float) -> str:
    return "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MODERATE" if score >= 4 else "LOW" if score else ""


def _epoch(stamp: str) -> float:
    """Day precision is enough: the grace period is counted in days."""
    try:
        return dt.datetime.strptime(stamp[:10], "%Y-%m-%d").timestamp()
    except ValueError:
        return 0.0
