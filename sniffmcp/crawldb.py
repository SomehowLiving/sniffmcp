"""SQLite store for the ecosystem crawl: registry entries, remote endpoint
snapshots, manifest changes, and npm/PyPI release history.

Snapshots are stored only when a manifest changes; every probe is logged
separately so availability and auth stats stay honest.
Default path ~/.sniffmcp/crawl.db (override with SNIFFMCP_CRAWL_DB or --db).
"""
from __future__ import annotations
import json, os, sqlite3, time

SCHEMA = """
CREATE TABLE IF NOT EXISTS servers(
  name TEXT PRIMARY KEY, version TEXT, title TEXT, description TEXT, repo_url TEXT,
  status TEXT, published_at TEXT, updated_at TEXT, raw TEXT, first_seen REAL, last_seen REAL);
CREATE TABLE IF NOT EXISTS server_versions(
  name TEXT, version TEXT, published_at TEXT, first_seen REAL, PRIMARY KEY(name, version));
CREATE TABLE IF NOT EXISTS endpoints(
  id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT UNIQUE, transport TEXT, server_name TEXT,
  auth_declared INTEGER, skip_reason TEXT, first_seen REAL, last_seen REAL);
CREATE TABLE IF NOT EXISTS probes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint_id INTEGER, taken_at REAL, status TEXT,
  error TEXT, manifest_hash TEXT, duration_ms INTEGER);
CREATE TABLE IF NOT EXISTS snapshots(
  id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint_id INTEGER, taken_at REAL, manifest_hash TEXT,
  manifest TEXT, protocol_version TEXT, tool_count INTEGER, score INTEGER, grade TEXT, findings TEXT);
CREATE TABLE IF NOT EXISTS changes(
  id INTEGER PRIMARY KEY AUTOINCREMENT, endpoint_id INTEGER, detected_at REAL, from_hash TEXT,
  to_hash TEXT, kind TEXT, severity TEXT, title TEXT, tool_name TEXT, evidence TEXT);
CREATE TABLE IF NOT EXISTS packages(
  ecosystem TEXT, name TEXT, server_name TEXT, first_seen REAL, last_checked REAL, error TEXT,
  PRIMARY KEY(ecosystem, name));
CREATE TABLE IF NOT EXISTS package_versions(
  ecosystem TEXT, name TEXT, version TEXT, published_at TEXT, install_scripts TEXT,
  publisher TEXT, provenance INTEGER, sdist_only INTEGER, integrity TEXT, first_seen REAL,
  PRIMARY KEY(ecosystem, name, version));
CREATE TABLE IF NOT EXISTS package_events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ecosystem TEXT, name TEXT, version TEXT,
  published_at TEXT, detected_at REAL, kind TEXT, severity TEXT, detail TEXT,
  UNIQUE(ecosystem, name, version, kind));
CREATE TABLE IF NOT EXISTS package_advisories(
  ecosystem TEXT, name TEXT, vuln_id TEXT, kind TEXT, severity TEXT, summary TEXT, aliases TEXT,
  affects_latest INTEGER, latest_version TEXT, first_seen REAL, last_seen REAL,
  PRIMARY KEY(ecosystem, name, vuln_id));
CREATE TABLE IF NOT EXISTS crawl_runs(
  id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT, started_at REAL, finished_at REAL,
  status TEXT, stages TEXT);
CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT);
CREATE INDEX IF NOT EXISTS probes_ep ON probes(endpoint_id, taken_at);
CREATE INDEX IF NOT EXISTS snaps_ep ON snapshots(endpoint_id, id);
"""


def default_path() -> str:
    return os.environ.get("SNIFFMCP_CRAWL_DB") or os.path.join(
        os.path.expanduser("~"), ".sniffmcp", "crawl.db")


class CrawlDB:
    def __init__(self, path: str | None = None):
        path = path or default_path()
        if path != ":memory:":
            os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        self.conn = sqlite3.connect(path, timeout=60)   # wait for other writers (e.g. a concurrent rescore) instead of failing
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def q(self, sql, *args) -> list[dict]:
        return [dict(r) for r in self.conn.execute(sql, args)]

    def one(self, sql, *args):
        row = self.conn.execute(sql, args).fetchone()
        return row[0] if row else None

    # ---- registry ----
    def upsert_server(self, entry: dict, now: float) -> None:
        s, meta = entry["server"], entry.get("_meta", {}).get("io.modelcontextprotocol.registry/official", {})
        self.conn.execute(
            "INSERT INTO servers(name,version,title,description,repo_url,status,published_at,updated_at,raw,first_seen,last_seen)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET version=excluded.version,"
            " title=excluded.title, description=excluded.description, repo_url=excluded.repo_url,"
            " status=excluded.status, published_at=excluded.published_at, updated_at=excluded.updated_at,"
            " raw=excluded.raw, last_seen=excluded.last_seen",
            (s["name"], s.get("version"), s.get("title"), s.get("description"),
             (s.get("repository") or {}).get("url"), meta.get("status"), meta.get("publishedAt"),
             meta.get("updatedAt"), json.dumps(s), now, now))
        self.conn.execute("INSERT OR IGNORE INTO server_versions(name,version,published_at,first_seen) VALUES(?,?,?,?)",
                          (s["name"], s.get("version"), meta.get("publishedAt"), now))

    def upsert_endpoint(self, url, transport, server_name, auth_declared, skip_reason, now) -> None:
        self.conn.execute(
            "INSERT INTO endpoints(url,transport,server_name,auth_declared,skip_reason,first_seen,last_seen)"
            " VALUES(?,?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET transport=excluded.transport,"
            " server_name=excluded.server_name, auth_declared=excluded.auth_declared,"
            " skip_reason=excluded.skip_reason, last_seen=excluded.last_seen",
            (url, transport, server_name, int(auth_declared), skip_reason, now, now))

    def upsert_package(self, ecosystem, name, server_name, now) -> None:
        self.conn.execute("INSERT OR IGNORE INTO packages(ecosystem,name,server_name,first_seen) VALUES(?,?,?,?)",
                          (ecosystem, name, server_name, now))

    # ---- probes / snapshots ----
    def due_endpoints(self, min_age_s: float, limit: int | None, per_host_cap: int | None = None) -> list[dict]:
        """Stalest first (never-probed, then oldest), at most per_host_cap per host per run.
        Bulk publishers register thousands of entries on one host; the cap samples them
        on rotation instead of hitting one operator thousands of times a day."""
        from urllib.parse import urlparse
        sql = ("SELECT e.*, COALESCE((SELECT MAX(taken_at) FROM probes p WHERE p.endpoint_id=e.id), 0) AS last_probe"
               " FROM endpoints e WHERE e.skip_reason IS NULL AND last_probe < ? ORDER BY last_probe, e.id")
        rows, per_host = [], {}
        for r in self.q(sql, time.time() - min_age_s):
            host = urlparse(r["url"]).hostname or ""
            if per_host_cap and per_host.get(host, 0) >= per_host_cap:
                continue
            per_host[host] = per_host.get(host, 0) + 1
            rows.append(r)
        return rows[:limit] if limit else rows

    def last_snapshot(self, endpoint_id) -> dict | None:
        rows = self.q("SELECT * FROM snapshots WHERE endpoint_id=? ORDER BY id DESC LIMIT 1", endpoint_id)
        return rows[0] if rows else None

    def meta(self, key: str):
        return self.one("SELECT value FROM meta WHERE key=?", key)

    def set_meta(self, key: str, value) -> None:
        self.conn.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                          (key, str(value)))
        self.conn.commit()

    def commit(self):
        self.conn.commit()
