"""Ecosystem crawler: the official MCP registry -> remote manifest snapshots and
npm/PyPI release history, stored over time in crawldb.

Rules this crawler keeps:
  - Probes only public addresses. Registry entries are untrusted; one pointing at
    localhost, a LAN range or cloud metadata must not turn this into an SSRF tool.
  - Only list calls (tools/resources/prompts). Never calls a tool.
  - At most one probe per endpoint per --min-age hours; at most 2 concurrent per host.
  - Endpoints whose registry entry declares a required auth header are probed without
    credentials too (the header is often optional); once they answer 401/403 they are
    re-checked weekly, not daily.
  - Packages are never downloaded or executed: npm/PyPI metadata only.
  - Stores facts (what changed, when). Verdicts stay in local reports.
"""
from __future__ import annotations
import asyncio, ipaddress, json, socket, statistics, time
from collections import Counter
from urllib.parse import urlparse, quote

import httpx2

from . import __version__, osv
from .checks import ManifestContext, check_rug_pull
from .client import ConnectError, fetch_manifest
from .crawldb import CrawlDB
from .engine import report_from_manifest
from .injection import scan_text
from .models import canonical_manifest_hash

REGISTRY = "https://registry.modelcontextprotocol.io/v0/servers"
USER_AGENT = f"sniffmcp-crawler/{__version__} (MCP ecosystem research; list calls only, ~1 probe/day)"
CLIENT_NAME = "sniffmcp-crawler"
DAY = 86400


# ---------------------------------------------------------------- registry
FULL_SYNC_EVERY = 7 * DAY


async def sync_registry(db: CrawlDB, page_size: int = 100, max_pages: int = 1000,
                        full: bool | None = None) -> dict:
    """Incremental by default: only entries the registry updated since the last sync (minus an
    hour of overlap), which is a few pages instead of ~400 slow ones. A full sync runs weekly,
    when forced, or on a fresh database, so nothing drifts."""
    started = time.time()
    last_sync = float(db.meta("last_sync") or 0)
    last_full = float(db.meta("last_full_sync") or 0)
    if full is None:
        full = not last_sync or started - last_full > FULL_SYNC_EVERY
    cursor, n = None, 0
    async with httpx2.AsyncClient(timeout=60, headers={"User-Agent": USER_AGENT}) as http:
        for _ in range(max_pages):
            params = {"limit": page_size, "version": "latest"}
            if not full:
                params["updated_since"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(last_sync - 3600))
            if cursor:
                params["cursor"] = cursor
            data = await _get_json(http, REGISTRY, params)
            for entry in data.get("servers", []):
                _ingest(db, entry, started)
                n += 1
            db.commit()
            cursor = (data.get("metadata") or {}).get("nextCursor")
            if not cursor:
                break
    db.set_meta("last_sync", started)
    if full:
        db.set_meta("last_full_sync", started)
    return {"servers": n, "mode": "full" if full else "incremental"}


async def _get_json(http, url, params, attempts: int = 4) -> dict:
    """The registry is slow (10-20s pages) and returns occasional 5xx; back off and retry."""
    for i in range(attempts):
        try:
            r = await http.get(url, params=params)
            if r.status_code < 500:
                r.raise_for_status()
                return r.json()
            err = f"HTTP {r.status_code}"
        except (httpx2.TransportError, httpx2.TimeoutException) as e:
            err = f"{type(e).__name__}: {e}"
        if i < attempts - 1:
            await asyncio.sleep(5 * 3 ** i)
    raise RuntimeError(f"registry unavailable after {attempts} attempts ({err}); progress so far is saved")


def _ingest(db: CrawlDB, entry: dict, now: float) -> None:
    s = entry["server"]
    db.upsert_server(entry, now)
    for rem in s.get("remotes") or []:
        url = rem.get("url") or ""
        transport = "sse" if rem.get("type") == "sse" else "streamable_http"
        auth = any(h.get("isRequired") for h in rem.get("headers") or [])
        skip = ("templated-url" if "{" in url
                else None if url.startswith(("https://", "http://")) else "bad-url")
        db.upsert_endpoint(url, transport, s["name"], auth, skip, now)
    for pkg in s.get("packages") or []:
        eco = {"npm": "npm", "pypi": "pypi"}.get(pkg.get("registryType"))
        if eco and pkg.get("identifier"):
            db.upsert_package(eco, pkg["identifier"], s["name"], now)


# ---------------------------------------------------------------- remotes
async def public_address_check(url: str) -> str | None:
    """None if the URL resolves only to globally routable addresses, else the reason."""
    u = urlparse(url)
    if u.scheme not in ("https", "http") or not u.hostname:
        return "bad-url"
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(u.hostname, u.port or 443,
                                                              type=socket.SOCK_STREAM)
    except OSError:
        return "dns-failure"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0].split("%")[0])
        if not ip.is_global:
            return "non-public-address"
    return None


async def probe_remotes(db: CrawlDB, concurrency: int = 8, per_host: int = 2,
                        min_age_h: float = 20, limit: int | None = None, timeout: float = 20,
                        per_host_cap: int | None = 100, progress=None) -> dict:
    due = db.due_endpoints(min_age_h * 3600, limit, per_host_cap)
    total_sem = asyncio.Semaphore(concurrency)
    host_sems: dict[str, asyncio.Semaphore] = {}
    stats: Counter = Counter()

    async def one(ep):
        host = urlparse(ep["url"]).hostname or ""
        hs = host_sems.setdefault(host, asyncio.Semaphore(per_host))
        async with hs, total_sem:   # host slot first, so one busy host can't park every global slot
            status, err, mhash, t0 = await _probe(db, ep, timeout)
        db.conn.execute("INSERT INTO probes(endpoint_id,taken_at,status,error,manifest_hash,duration_ms)"
                        " VALUES(?,?,?,?,?,?)", (ep["id"], time.time(), status, err, mhash,
                                                 int((time.time() - t0) * 1000)))
        db.commit()
        stats[status] += 1
        if progress:
            progress(sum(stats.values()), len(due), ep["url"], status)

    await asyncio.gather(*(one(ep) for ep in due))
    return {"probed": len(due), **stats}


async def _probe(db: CrawlDB, ep: dict, timeout: float):
    t0 = time.time()
    blocked = await public_address_check(ep["url"])
    if blocked == "dns-failure":
        return "error", "DNS lookup failed", None, t0
    if blocked:
        return "skipped", blocked, None, t0
    config = {"url": ep["url"], "headers": {"User-Agent": USER_AGENT}, "timeout": timeout}
    if ep["transport"] == "sse":
        config["type"] = "sse"
    try:
        manifest = await fetch_manifest(config, client_name=CLIENT_NAME, auth="none")   # never the user's logins
    except ConnectError as e:
        msg = str(e)
        status = ("auth" if msg.startswith("requires authentication") else
                  "timeout" if msg.startswith("timed out") else "error")
        return status, msg[:300], None, t0
    except Exception as e:  # never let one endpoint kill the crawl
        return "error", f"{type(e).__name__}: {e}"[:300], None, t0
    # server instructions are model-visible too, so they're part of the change hash
    mhash = canonical_manifest_hash([{"name": "__instructions__", "description": manifest.get("instructions") or ""}]
                                    + manifest["tools"], manifest.get("resources"), manifest.get("prompts"))
    prev = db.last_snapshot(ep["id"])
    if not prev or prev["manifest_hash"] != mhash:
        _record_snapshot(db, ep, manifest, mhash, prev)
    return "ok", None, mhash, t0


def _record_snapshot(db: CrawlDB, ep: dict, manifest: dict, mhash: str, prev: dict | None) -> None:
    now = time.time()
    rep = report_from_manifest({"url": ep["url"]}, manifest)
    findings = [f.__dict__ for f in rep.findings if f.severity != "info"]
    stored = {k: manifest.get(k) for k in ("tools", "resources", "prompts", "instructions",
                                           "server_info", "protocol_version")}
    db.conn.execute(
        "INSERT INTO snapshots(endpoint_id,taken_at,manifest_hash,manifest,protocol_version,tool_count,score,grade,findings)"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        (ep["id"], now, mhash, json.dumps(stored), manifest.get("protocol_version"),
         len(manifest["tools"]), rep.score, rep.grade, json.dumps(findings)))
    if not prev:
        return
    changes = compute_changes(json.loads(prev["manifest"]), manifest, ep)
    db.conn.executemany(
        "INSERT INTO changes(endpoint_id,detected_at,from_hash,to_hash,kind,severity,title,tool_name,evidence)"
        " VALUES(?,?,?,?,?,?,?,?,?)",
        [(ep["id"], now, prev["manifest_hash"], mhash, *c) for c in changes])


def compute_changes(old: dict, manifest: dict, ep: dict) -> list[tuple]:
    """(kind, severity, title, tool_name, evidence) between two stored manifests."""
    ctx = ManifestContext(ep["url"], ep["transport"], {"url": ep["url"]}, manifest.get("tools") or [],
                          manifest.get("resources"), manifest.get("prompts"),
                          prior_manifest={"tools": old.get("tools") or []})
    changes = [(f.kind or "benign", f.severity, f.title, f.tool_name, f.evidence) for f in check_rug_pull(ctx)]
    if (old.get("instructions") or "") != (manifest.get("instructions") or ""):
        old_labels = {h[0] for h in scan_text(old.get("instructions") or "")}
        new_hits = [h for h in scan_text(manifest.get("instructions") or "") if h[0] not in old_labels]
        changes.append(("risky" if new_hits else "benign", "critical" if new_hits else "info",
                        "Server instructions changed" + (f": {new_hits[0][0]}" if new_hits else ""), None,
                        (manifest.get("instructions") or "")[:200]))
    return changes or [("benign", "info", "Resources or prompts changed", None, "")]


def rescore(db: CrawlDB) -> int:
    """Re-run the current rules over every stored snapshot and re-classify every stored change
    between consecutive snapshots (after a rule fix)."""
    rows = db.q("SELECT s.id, s.endpoint_id, s.manifest, s.manifest_hash, s.taken_at, e.url, e.transport"
                " FROM snapshots s JOIN endpoints e ON e.id=s.endpoint_id ORDER BY s.endpoint_id, s.id")
    changes, prev = [], None
    for r in rows:
        manifest = json.loads(r["manifest"])
        rep = report_from_manifest({"url": r["url"]}, manifest)
        db.conn.execute("UPDATE snapshots SET score=?, grade=?, findings=? WHERE id=?",
                        (rep.score, rep.grade, json.dumps([f.__dict__ for f in rep.findings if f.severity != "info"]),
                         r["id"]))
        if prev and prev["endpoint_id"] == r["endpoint_id"]:
            ep = {"url": r["url"], "transport": r["transport"]}
            changes += [(r["endpoint_id"], r["taken_at"], prev["manifest_hash"], r["manifest_hash"], *c)
                        for c in compute_changes(json.loads(prev["manifest"]), manifest, ep)]
        prev = r
    db.conn.execute("DELETE FROM changes")
    db.conn.executemany(
        "INSERT INTO changes(endpoint_id,detected_at,from_hash,to_hash,kind,severity,title,tool_name,evidence)"
        " VALUES(?,?,?,?,?,?,?,?,?)", changes)
    db.commit()
    return len(rows)


# ---------------------------------------------------------------- packages
INSTALL_HOOKS = ("preinstall", "install", "postinstall")


def npm_versions(doc: dict) -> list[dict]:
    times = doc.get("time") or {}
    out = []
    for ver, v in (doc.get("versions") or {}).items():
        scripts = {k: v["scripts"][k] for k in INSTALL_HOOKS if k in (v.get("scripts") or {})}
        user = v.get("_npmUser") or {}
        dist = v.get("dist") or {}
        out.append({"version": ver, "published_at": times.get(ver),
                    "install_scripts": scripts, "publisher": user.get("name"),
                    "provenance": bool(dist.get("attestations") or user.get("trustedPublisher")),
                    "sdist_only": False, "integrity": dist.get("integrity")})
    return sorted(out, key=lambda x: x["published_at"] or "")


def pypi_versions(doc: dict) -> list[dict]:
    out = []
    for ver, files in (doc.get("releases") or {}).items():
        if not files:
            continue
        out.append({"version": ver,
                    "published_at": min(f.get("upload_time_iso_8601") or "" for f in files),
                    "install_scripts": {}, "publisher": None, "provenance": False,
                    "sdist_only": all(f.get("packagetype") == "sdist" for f in files),
                    "integrity": (files[0].get("digests") or {}).get("sha256")})
    return sorted(out, key=lambda x: x["published_at"] or "")


def release_events(versions: list[dict]) -> list[tuple[str, str, str, str, str]]:
    """(version, published_at, kind, severity, detail) over the full release history.
    Signals, not verdicts: each is a known precursor in package takeovers."""
    events, publishers, prev = [], set(), None
    for v in versions:
        if v["install_scripts"] and (prev is None or not prev["install_scripts"]):
            events.append((v["version"], v["published_at"],
                           "install-script-added" if prev else "install-script", "high" if prev else "medium",
                           json.dumps(v["install_scripts"])[:300]))
        if prev and prev["provenance"] and not v["provenance"]:
            events.append((v["version"], v["published_at"], "provenance-dropped", "high",
                           f"{prev['version']} had provenance/trusted publishing; {v['version']} does not"))
        # A move *to* trusted publishing (provenance on) is an improvement, not a takeover.
        if v["publisher"] and publishers and v["publisher"] not in publishers and not v["provenance"]:
            events.append((v["version"], v["published_at"], "new-publisher", "medium",
                           f"first release by '{v['publisher']}' (previous: {', '.join(sorted(publishers))[:200]})"))
        if prev and v["sdist_only"] and not prev["sdist_only"]:
            events.append((v["version"], v["published_at"], "wheel-dropped", "medium",
                           "source-only release: installing runs the package's build code"))
        if v["publisher"]:
            publishers.add(v["publisher"])
        prev = v
    return events


async def crawl_packages(db: CrawlDB, concurrency: int = 8, min_age_h: float = 20,
                         limit: int | None = None, progress=None) -> dict:
    cutoff = time.time() - min_age_h * 3600
    due = db.q("SELECT * FROM packages WHERE COALESCE(last_checked,0) < ? ORDER BY ecosystem, name", cutoff)
    due = due[:limit] if limit else due
    sem, stats = asyncio.Semaphore(concurrency), Counter()
    async with httpx2.AsyncClient(timeout=30, headers={"User-Agent": USER_AGENT}) as http:
        async def one(p):
            async with sem:
                status = await _crawl_package(db, http, p)
            stats[status] += 1
            if progress:
                progress(sum(stats.values()), len(due), f"{p['ecosystem']}:{p['name']}", status)
        await asyncio.gather(*(one(p) for p in due))
    return {"checked": len(due), **stats}


async def _crawl_package(db: CrawlDB, http, p: dict) -> str:
    eco, name, now = p["ecosystem"], p["name"], time.time()
    url = (f"https://registry.npmjs.org/{quote(name, safe='@')}" if eco == "npm"
           else f"https://pypi.org/pypi/{quote(name)}/json")
    try:
        r = await http.get(url)
        if r.status_code == 404:
            raise LookupError("not found on registry")
        r.raise_for_status()
        versions = npm_versions(r.json()) if eco == "npm" else pypi_versions(r.json())
    except Exception as e:
        db.conn.execute("UPDATE packages SET last_checked=?, error=? WHERE ecosystem=? AND name=?",
                        (now, f"{type(e).__name__}: {e}"[:300], eco, name))
        db.commit()
        return "error"
    db.conn.executemany(
        "INSERT OR IGNORE INTO package_versions(ecosystem,name,version,published_at,install_scripts,"
        "publisher,provenance,sdist_only,integrity,first_seen) VALUES(?,?,?,?,?,?,?,?,?,?)",
        [(eco, name, v["version"], v["published_at"], json.dumps(v["install_scripts"]), v["publisher"],
          int(v["provenance"]), int(v["sdist_only"]), v["integrity"], now) for v in versions])
    db.conn.executemany(
        "INSERT OR IGNORE INTO package_events(ecosystem,name,version,published_at,detected_at,kind,severity,detail)"
        " VALUES(?,?,?,?,?,?,?,?)", [(eco, name, *e[:2], now, *e[2:]) for e in release_events(versions)])
    db.conn.execute("UPDATE packages SET last_checked=?, error=NULL WHERE ecosystem=? AND name=?", (now, eco, name))
    db.commit()
    return "ok"


# ---------------------------------------------------------------- advisories
async def crawl_advisories(db: CrawlDB) -> dict:
    """OSV for every tracked package: malware (MAL-) in any version, plus advisories
    affecting the current latest version. Old CVEs on superseded versions are skipped."""
    rows = db.q("SELECT ecosystem, name, version, published_at FROM package_versions")
    latest: dict[tuple[str, str], tuple[str, str]] = {}
    for r in rows:
        key = (r["ecosystem"], r["name"])
        if key not in latest or (r["published_at"] or "") > latest[key][1]:
            latest[key] = (r["version"], r["published_at"] or "")
    keys = sorted(latest)
    now = time.time()
    async with httpx2.AsyncClient(timeout=60, headers={"User-Agent": USER_AGENT}) as http:
        at_latest = await osv.query_batch(http, [(e, n, latest[(e, n)][0]) for e, n in keys])
        any_ver = await osv.query_batch(http, [(e, n, None) for e, n in keys])
        wanted: dict[tuple[str, str], dict[str, bool]] = {}
        for k, lat, anyv in zip(keys, at_latest, any_ver):
            ids = {i: True for i in lat}
            ids.update({i: i in lat for i in anyv if i.startswith("MAL-")})
            if ids:
                wanted[k] = ids
        info = await osv.details(http, {i for ids in wanted.values() for i in ids})
    for (eco, name), ids in wanted.items():
        for vid, affects in ids.items():
            v = info.get(vid, {"id": vid})
            db.conn.execute(
                "INSERT INTO package_advisories(ecosystem,name,vuln_id,kind,severity,summary,aliases,affects_latest,"
                "latest_version,first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(ecosystem,name,vuln_id)"
                " DO UPDATE SET affects_latest=excluded.affects_latest, latest_version=excluded.latest_version,"
                " severity=excluded.severity, summary=excluded.summary, last_seen=excluded.last_seen",
                (eco, name, vid, "malware" if vid.startswith("MAL-") else "vulnerability", osv.severity(v),
                 (v.get("summary") or "")[:300], json.dumps(v.get("aliases") or []), int(affects),
                 latest[(eco, name)][0], now, now))
    db.commit()
    mal = sum(1 for ids in wanted.values() if any(i.startswith("MAL-") for i in ids))
    return {"packages": len(keys), "with_advisories": len(wanted), "with_malware_history": mal}


# ---------------------------------------------------------------- status
def status(db: CrawlDB, days: int = 14) -> str:
    """Is the history healthy? Last runs, days with no successful crawl, stage failures."""
    now = time.time()
    runs = db.q("SELECT * FROM crawl_runs ORDER BY id DESC LIMIT 10")
    ok_days = {time.strftime("%Y-%m-%d", time.gmtime(r["started_at"]))
               for r in db.q("SELECT started_at FROM crawl_runs WHERE action='run' AND status!='failed'")}
    # days before run-tracking existed: count a day as covered if probes happened that day
    probe_days = {r["d"] for r in db.q(
        "SELECT DISTINCT strftime('%Y-%m-%d', taken_at, 'unixepoch') AS d FROM probes WHERE taken_at > ?",
        now - days * DAY)}
    covered = ok_days | probe_days
    first = min(covered) if covered else None
    window = [time.strftime("%Y-%m-%d", time.gmtime(now - i * DAY)) for i in range(days - 1, -1, -1)]
    window = [d for d in window if first and d >= first]
    gaps = [d for d in window if d not in covered]
    last_ok = db.one("SELECT MAX(finished_at) FROM crawl_runs WHERE action='run' AND status!='failed'") \
        or db.one("SELECT MAX(taken_at) FROM probes")
    age_h = (now - last_ok) / 3600 if last_ok else None
    health = "OK" if age_h is not None and age_h < 30 else "STALE"
    L = [f"crawl health: {health}" + (f" (last successful crawl {age_h:.1f}h ago)" if age_h is not None else " (never)"),
         f"days covered since {first}: {len(window) - len(gaps)}/{len(window)}"
         + (f"  gaps: {', '.join(gaps)}" if gaps else "  (no gaps)"), "", "recent runs:"]
    for r in runs:
        st = json.loads(r["stages"] or "{}")
        bad = [k for k, v in st.items() if not v.get("ok")]
        dur = (r["finished_at"] - r["started_at"]) / 60 if r["finished_at"] else 0
        L.append(f"  {time.strftime('%Y-%m-%d %H:%M', time.gmtime(r['started_at']))}Z  {r['action']:8} "
                 f"{r['status']:8} {dur:5.0f} min" + (f"  failed: {', '.join(bad)}" if bad else ""))
    if not runs:
        L.append("  (no tracked runs yet)")
    return "\n".join(L)


# ---------------------------------------------------------------- digest
def digest(db: CrawlDB, hours: int = 26, weekly: bool = False) -> tuple[str, bool]:
    """Short email-sized summary of the last crawl window. Returns (markdown, notable).
    notable = something a human should look at: risky manifest changes, high-severity package
    signals, new malware advisories, or an unhealthy/failed crawl."""
    since = time.time() - hours * 3600
    since_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(since))
    health = status(db).splitlines()[0]
    last_run = (db.q("SELECT status FROM crawl_runs WHERE action='run' ORDER BY id DESC LIMIT 1") or [{"status": "?"}])[0]["status"]
    ch = db.q("SELECT c.kind, c.severity, c.title, e.server_name FROM changes c JOIN endpoints e ON e.id=c.endpoint_id"
              " WHERE c.detected_at>?", since)
    risky = [c for c in ch if c["kind"] == "risky"]
    changed = db.one("SELECT COUNT(DISTINCT endpoint_id) FROM changes WHERE detected_at>?", since) or 0
    probed = db.one("SELECT COUNT(DISTINCT endpoint_id) FROM probes WHERE taken_at>? AND status='ok'", since) or 0
    pkg = db.q("SELECT ecosystem, name, version, kind, detail FROM package_events WHERE published_at>=? "
               "AND severity='high' ORDER BY published_at DESC", since_iso)
    mal = db.q("SELECT ecosystem, name, vuln_id, summary, affects_latest FROM package_advisories "
               "WHERE kind='malware' AND first_seen>?", since)
    # "Already wrong" on arrival: a server seen for the first time in this window whose first snapshot
    # has high/critical findings never shows up as a *change*. (Duplicate tool names, SM-08, is the
    # bulk-clone pattern already tracked separately.)
    arrived = []
    for r in db.q("SELECT e.server_name, s.findings FROM snapshots s JOIN endpoints e ON e.id=s.endpoint_id"
                  " WHERE s.taken_at>? AND s.id=(SELECT MIN(id) FROM snapshots WHERE endpoint_id=s.endpoint_id)", since):
        bad = [f for f in json.loads(r["findings"] or "[]")
               if f["severity"] in ("high", "critical") and f["check_id"] != "SM-08"]
        if bad:
            arrived.append((r["server_name"], bad[0]["title"]))
    # Email-worthy only: high/critical drift, new malware, or an unhealthy crawl. Medium drift and
    # package signals (hundreds of provenance drops are normal) wait for the weekly summary.
    urgent = [c for c in risky if c["severity"] in ("high", "critical")]
    notable = bool(urgent or mal or arrived) or not health.startswith("crawl health: OK") or last_run in ("failed", "partial")
    if not weekly:
        risky, pkg = urgent, []
    head = "📅 Weekly summary" if weekly else ("🚨 Needs a look" if notable else "✅ Quiet day")
    L = [f"**{head}** · {time.strftime('%Y-%m-%d')} · last run: `{last_run}`",
         "", f"- {health}",
         f"- servers checked: {probed:,} · changed: {changed:,} "
         f"({', '.join(f'{k} {v}' for k, v in Counter(c['kind'] for c in ch).most_common()) or 'no changes'})", ""]
    if risky:
        L += ["**Risky manifest changes** (verify by hand before acting):"]
        L += [f"- `{c['server_name']}`: {c['title'][:120]}" for c in risky[:10]]
        L += [f"- …and {len(risky) - 10} more" if len(risky) > 10 else ""]
    if arrived:
        L += ["**New servers that arrived with serious findings** (verify by hand):"]
        L += [f"- `{n}`: {t[:120]}" for n, t in arrived[:10]]
        L += [f"- …and {len(arrived) - 10} more" if len(arrived) > 10 else ""]
    if mal:
        L += ["**New malware advisories (OSV):**"]
        L += [f"- `{m['ecosystem']}:{m['name']}` {m['vuln_id']}" + (" ⚠️ affects latest" if m["affects_latest"] else "")
              for m in mal[:10]]
    if pkg:
        L += ["**High-severity package signals:**"]
        L += [f"- `{p['ecosystem']}:{p['name']}@{p['version']}` {p['kind']}" for p in pkg[:10]]
    L += ["", "_Leads, not verdicts. Full report attached to today's snapshot release._"]
    return "\n".join(x for x in L if x is not None), notable


# ---------------------------------------------------------------- report
def _cell(s, n=110) -> str:
    s = " ".join(str(s or "").split()).replace("`", "'").replace("|", "/")
    return f"`{s[:n]}{'…' if len(s) > n else ''}`" if s else ""


def _pct(a, b) -> str:
    return f"{100 * a / b:.0f}%" if b else "–"


def report(db: CrawlDB, days: int = 7) -> str:
    since = time.time() - days * DAY
    since_iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(since))
    L = [f"# MCP ecosystem crawl — {time.strftime('%Y-%m-%d')}", ""]

    servers = db.one("SELECT COUNT(*) FROM servers")
    active = db.one("SELECT COUNT(*) FROM servers WHERE status='active'")
    with_remote = db.one("SELECT COUNT(DISTINCT server_name) FROM endpoints")
    pk = Counter({r["ecosystem"]: r["n"] for r in db.q("SELECT ecosystem, COUNT(*) n FROM packages GROUP BY ecosystem")})
    pubs = Counter(r["name"].split("/")[0] for r in db.q("SELECT name FROM servers"))
    bulk = [(p, n) for p, n in pubs.most_common(10) if n >= 100]
    hosts = Counter(urlparse(r["url"]).hostname for r in db.q("SELECT url FROM endpoints"))
    L += ["## Registry", f"- {servers} servers in the official registry ({active} active), "
          f"from {len(pubs)} publisher namespaces",
          f"- bulk publishers (≥100 entries): " + (", ".join(f"{p} {n}" for p, n in bulk) or "none"),
          f"- busiest endpoint hosts: " + ", ".join(f"{h} {n}" for h, n in hosts.most_common(5)),
          f"- {with_remote} with remote endpoints; packages tracked: "
          + ", ".join(f"{k} {v}" for k, v in sorted(pk.items())), ""]

    skip = Counter({r["skip_reason"] or "probed": r["n"] for r in
                    db.q("SELECT skip_reason, COUNT(*) n FROM endpoints GROUP BY skip_reason")})
    latest = db.q("SELECT p.status, p.error, e.url, e.server_name, e.id, e.auth_declared FROM probes p JOIN endpoints e ON e.id=p.endpoint_id"
                  " WHERE p.id=(SELECT MAX(id) FROM probes WHERE endpoint_id=p.endpoint_id)")
    st = Counter(r["status"] for r in latest)
    n_ep, n_probed = sum(skip.values()), len(latest)
    # rates over endpoints we have evidence for: declared-auth ones plus those actually probed
    known = skip.get("auth-declared", 0) + n_probed
    auth_total = skip.get("auth-declared", 0) + st.get("auth", 0)
    L += ["## Remote endpoints", f"- {n_ep} endpoints: " + ", ".join(f"{k} {v}" for k, v in skip.most_common()),
          f"- probed so far: {n_probed} of {skip.get('probed', 0)}; latest result: "
          + ", ".join(f"{k} {v}" for k, v in st.most_common()),
          f"- **require auth: {auth_total} of {known} known ({_pct(auth_total, known)})** "
          f"(declared in registry {skip.get('auth-declared', 0)}, 401/403 on probe {st.get('auth', 0)})",
          f"- **openly scannable: {st.get('ok', 0)} of {n_probed} probed ({_pct(st.get('ok', 0), n_probed)})**"]
    decl = [r for r in latest if r["auth_declared"]]
    if decl:
        open_decl = sum(r["status"] == "ok" for r in decl)
        L += [f"- declared auth in the registry but answered without it: {open_decl} of {len(decl)} probed "
              f"({_pct(open_decl, len(decl))})"]
    L += [""]

    ok_ids = [r["id"] for r in latest if r["status"] == "ok"]
    snaps = [db.last_snapshot(i) for i in ok_ids]
    snaps = [s for s in snaps if s]
    if snaps:
        grades = Counter(s["grade"] for s in snaps)
        protos = Counter(s["protocol_version"] for s in snaps)
        tools = [s["tool_count"] for s in snaps]
        toks = [len(json.dumps(json.loads(s["manifest"]).get("tools") or [])) // 4 for s in snaps]
        q90 = lambda xs: sorted(xs)[int(0.9 * (len(xs) - 1))]
        L += ["### Reachable servers", f"- grades: " + ", ".join(f"{g} {grades.get(g, 0)}" for g in "ABCDF"),
              f"- protocol versions: " + ", ".join(f"{k} {v}" for k, v in protos.most_common()),
              f"- tools per server: median {statistics.median(tools):.0f}, p90 {q90(tools)}, max {max(tools)}",
              f"- tool-definition tokens per server (≈chars/4): median {statistics.median(toks):,.0f}, "
              f"p90 {q90(toks):,}, max {max(toks):,}", ""]
        by_check: Counter = Counter()
        serious = []
        name_of = {r["id"]: r["server_name"] for r in latest}
        for s in snaps:
            fs = json.loads(s["findings"])
            for cid in {f["check_id"] for f in fs if f["severity"] in ("medium", "high", "critical")}:
                by_check[cid] += 1
            serious += [(name_of.get(s["endpoint_id"]), f) for f in fs if f["severity"] in ("high", "critical")]
        L += ["### Findings (servers with ≥1 medium+ finding, by check)",
              ", ".join(f"{k} {v}" for k, v in by_check.most_common()) or "none", ""]
        if serious:
            L += ["### High / critical findings — verify by hand before citing", "",
                  "| server | severity | finding | evidence |", "|---|---|---|---|"]
            L += [f"| {_cell(n, 50)} | {f['severity']} | {_cell(f['title'], 70)} | {_cell(f['evidence'])} |"
                  for n, f in serious[:60]]
            L.append("")

    ch = db.q("SELECT c.*, e.server_name FROM changes c JOIN endpoints e ON e.id=c.endpoint_id"
              " WHERE c.detected_at>=? ORDER BY c.id", since)
    L += [f"## Manifest changes in the last {days} days",
          f"- {len(ch)} change records on {len({c['endpoint_id'] for c in ch})} endpoints: "
          + ", ".join(f"{k} {v}" for k, v in Counter(c["kind"] for c in ch).most_common()), ""]
    notable = [c for c in ch if c["kind"] != "benign"]
    if notable:
        L += ["| server | kind | severity | change | evidence |", "|---|---|---|---|---|"]
        L += [f"| {_cell(c['server_name'], 50)} | {c['kind']} | {c['severity']} | {_cell(c['title'], 70)} | {_cell(c['evidence'])} |"
              for c in notable[:60]]
        L.append("")

    recent = db.one("SELECT COUNT(*) FROM package_versions WHERE published_at>=?", since_iso)
    ev_all = Counter({(r["kind"]): r["n"] for r in db.q("SELECT kind, COUNT(*) n FROM package_events GROUP BY kind")})
    ev_recent = db.q("SELECT * FROM package_events WHERE published_at>=? AND severity IN ('high','medium')"
                     " ORDER BY published_at DESC", since_iso)
    errs = db.one("SELECT COUNT(*) FROM packages WHERE error IS NOT NULL")
    L += ["## Packages (npm / PyPI metadata; nothing executed)",
          f"- {recent} versions published in the last {days} days; {errs} packages not found or failed",
          f"- release-history signals, all time: " + (", ".join(f"{k} {v}" for k, v in ev_all.most_common()) or "none"),
          ""]
    if ev_recent:
        L += [f"### Signals on releases from the last {days} days", "",
              "| package | version | signal | detail |", "|---|---|---|---|"]
        L += [f"| {_cell(e['ecosystem'] + ':' + e['name'], 60)} | {_cell(e['version'], 20)} | {e['kind']} | {_cell(e['detail'])} |"
              for e in ev_recent[:60]]
        L.append("")
    adv = db.q("SELECT a.*, p.server_name FROM package_advisories a LEFT JOIN packages p"
               " ON p.ecosystem=a.ecosystem AND p.name=a.name")
    if adv:
        mal = [a for a in adv if a["kind"] == "malware"]
        vul = [a for a in adv if a["kind"] == "vulnerability" and a["affects_latest"]]
        sev = Counter(a["severity"] for a in vul)
        L += ["## Known advisories (OSV.dev)",
              f"- **malware advisories: {len({(a['ecosystem'], a['name']) for a in mal})} packages** "
              f"({len({(a['ecosystem'], a['name']) for a in mal if a['affects_latest']})} with the current latest version affected)",
              f"- latest version has known vulnerabilities: {len({(a['ecosystem'], a['name']) for a in vul})} packages "
              f"(advisories: " + ", ".join(f"{k} {v}" for k, v in sev.most_common()) + ")", ""]
        if mal:
            L += ["| package | registry entry | advisory | affects latest |", "|---|---|---|---|"]
            L += [f"| {_cell(a['ecosystem'] + ':' + a['name'], 50)} | {_cell(a['server_name'], 50)} | "
                  f"{_cell(a['vuln_id'] + ' ' + a['summary'], 80)} | {'yes' if a['affects_latest'] else 'no'} |" for a in mal[:60]]
            L.append("")
        top = [a for a in vul if a["severity"] == "high"]
        if top:
            L += ["### High-severity advisories on current latest versions", "",
                  "| package | latest | advisory |", "|---|---|---|"]
            L += [f"| {_cell(a['ecosystem'] + ':' + a['name'], 50)} | {_cell(a['latest_version'], 20)} | "
                  f"{_cell(a['vuln_id'] + ' ' + a['summary'], 90)} |" for a in top[:40]]
            L.append("")
    L += ["---", "Facts from automated list calls, registry metadata and OSV.dev. A finding is a lead to check, not a verdict."]
    return "\n".join(L)
