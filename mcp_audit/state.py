"""Local SQLite store for watches, baselines, snapshots and alerts.

Default path ~/.mcp_audit/state.db (override with MCP_AUDIT_STATE). Watch
configs can hold credentials from the user's client config, so the file is
created owner-read/write only.
"""
from __future__ import annotations
import json, os, sqlite3, time

SCHEMA = """
CREATE TABLE IF NOT EXISTS watches(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT UNIQUE NOT NULL,
  config TEXT NOT NULL,
  transport TEXT NOT NULL,
  interval_seconds INTEGER NOT NULL DEFAULT 3600,
  alert_webhook TEXT,
  baseline_hash TEXT,
  baseline_tools TEXT,
  created_at REAL,
  last_checked_at REAL);
CREATE TABLE IF NOT EXISTS snapshots(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  watch_id INTEGER REFERENCES watches(id),
  manifest_hash TEXT, tools TEXT, taken_at REAL);
CREATE TABLE IF NOT EXISTS alerts(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  watch_id INTEGER REFERENCES watches(id),
  severity TEXT, message TEXT, created_at REAL);
"""


def default_path() -> str:
    return os.environ.get("MCP_AUDIT_STATE") or os.path.join(
        os.path.expanduser("~"), ".mcp_audit", "state.db")


class Store:
    def __init__(self, path: str | None = None):
        path = path or default_path()
        if path != ":memory:":
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
            if not os.path.exists(path):
                os.close(os.open(path, os.O_CREAT | os.O_WRONLY, 0o600))
        self.conn = sqlite3.connect(path, timeout=60)   # wait for other writers (e.g. a concurrent rescore) instead of failing
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def add_watch(self, name, config, transport, interval_seconds=3600, alert_webhook=None) -> None:
        """Create or update a watch. Re-adding keeps the existing baseline."""
        self.conn.execute(
            "INSERT INTO watches(name,config,transport,interval_seconds,alert_webhook,created_at)"
            " VALUES(?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET config=excluded.config,"
            " transport=excluded.transport, interval_seconds=excluded.interval_seconds,"
            " alert_webhook=excluded.alert_webhook",
            (name, json.dumps(config), transport, int(interval_seconds), alert_webhook, time.time()))
        self.conn.commit()

    def get_watch(self, name) -> dict | None:
        row = self.conn.execute("SELECT * FROM watches WHERE name=?", (name,)).fetchone()
        return dict(row) if row else None

    def all_watches(self) -> list[dict]:
        return [dict(r) for r in self.conn.execute("SELECT * FROM watches ORDER BY name")]

    def remove_watch(self, name) -> bool:
        cur = self.conn.execute("DELETE FROM watches WHERE name=?", (name,))
        self.conn.commit()
        return cur.rowcount > 0

    def set_baseline(self, watch_id, manifest_hash, tools) -> None:
        self.conn.execute("UPDATE watches SET baseline_hash=?, baseline_tools=? WHERE id=?",
                          (manifest_hash, json.dumps(tools), watch_id))
        self.conn.commit()

    def record_snapshot(self, watch_id, manifest_hash, tools) -> None:
        now = time.time()
        last = self.conn.execute(
            "SELECT manifest_hash FROM snapshots WHERE watch_id=? ORDER BY id DESC LIMIT 1",
            (watch_id,)).fetchone()
        if not last or last["manifest_hash"] != manifest_hash:   # store changes, not every poll
            self.conn.execute("INSERT INTO snapshots(watch_id,manifest_hash,tools,taken_at) VALUES(?,?,?,?)",
                              (watch_id, manifest_hash, json.dumps(tools), now))
        self.conn.execute("UPDATE watches SET last_checked_at=? WHERE id=?", (now, watch_id))
        self.conn.commit()

    def last_snapshot_hash(self, watch_id) -> str | None:
        row = self.conn.execute(
            "SELECT manifest_hash FROM snapshots WHERE watch_id=? ORDER BY id DESC LIMIT 1",
            (watch_id,)).fetchone()
        return row["manifest_hash"] if row else None

    def record_check(self, watch_id) -> None:
        self.conn.execute("UPDATE watches SET last_checked_at=? WHERE id=?", (time.time(), watch_id))
        self.conn.commit()

    def log_alert(self, watch_id, severity, message) -> None:
        self.conn.execute("INSERT INTO alerts(watch_id,severity,message,created_at) VALUES(?,?,?,?)",
                          (watch_id, severity, message, time.time()))
        self.conn.commit()

    def alerts(self, watch_id=None, limit=50) -> list[dict]:
        q, args = "SELECT * FROM alerts", ()
        if watch_id is not None:
            q, args = q + " WHERE watch_id=?", (watch_id,)
        return [dict(r) for r in self.conn.execute(q + " ORDER BY id DESC LIMIT ?", (*args, limit))]
