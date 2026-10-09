"""Rug-pull engine. Re-fetches each watched server's manifest, diffs it against
the stored baseline, classifies each change (risky / breaking / benign), and
pushes risky changes to a webhook (Slack-compatible JSON).

Alerts fire once per manifest change, not on every poll. The baseline only
moves when the user accepts the change (`sniffmcp watch NAME --accept`).

Known limit: a server that only changes after N *tool calls* inside a live
session (Deadbugz) shows its clean face to every fresh connection we open.
Catching that needs a proxy in the agent's own session.
"""
from __future__ import annotations
import json, time, urllib.request
from .client import fetch_manifest, ConnectError
from .checks import ManifestContext, check_rug_pull
from .models import Finding, canonical_manifest_hash
from .state import Store

ALERT_SEVERITIES = ("critical", "high")


async def check_watch(store: Store, watch: dict) -> list[Finding]:
    config = json.loads(watch["config"])
    try:
        manifest = await fetch_manifest(config)
    except ConnectError as e:
        f = Finding("SM-03", "medium", f"watch '{watch['name']}' unreachable", str(e)[:300])
        store.log_alert(watch["id"], f.severity, f.title + " | " + f.evidence)
        store.record_check(watch["id"])
        return [f]
    tools = manifest["tools"]
    new_hash = canonical_manifest_hash(tools, manifest.get("resources"), manifest.get("prompts"))
    previous_hash = store.last_snapshot_hash(watch["id"])
    store.record_snapshot(watch["id"], new_hash, tools)

    if not watch.get("baseline_hash"):
        store.set_baseline(watch["id"], new_hash, tools)
        return []
    if new_hash == watch["baseline_hash"]:
        return []
    ctx = ManifestContext(watch["name"], watch["transport"], config, tools,
                          manifest.get("resources"), manifest.get("prompts"),
                          manifest.get("server_info"), manifest.get("instructions"),
                          prior_manifest={"tools": json.loads(watch.get("baseline_tools") or "[]")})
    findings = check_rug_pull(ctx)
    if new_hash != previous_hash:  # first time we see this version: alert once
        for f in findings:
            store.log_alert(watch["id"], f.severity, f"[{f.kind or 'change'}] {f.title} | {f.evidence}")
            if f.severity in ALERT_SEVERITIES:
                _push(watch.get("alert_webhook"), watch["name"], f)
    return findings


async def accept(store: Store, name: str) -> bool:
    """Move the baseline to the server's current manifest."""
    watch = store.get_watch(name)
    if not watch:
        return False
    manifest = await fetch_manifest(json.loads(watch["config"]))
    tools = manifest["tools"]
    store.set_baseline(watch["id"], canonical_manifest_hash(tools, manifest.get("resources"),
                                                            manifest.get("prompts")), tools)
    return True


def _push(webhook: str | None, name: str, finding: Finding) -> None:
    if not webhook:
        return
    text = f"[sniffmcp:{finding.severity.upper()}] {name}: {finding.title}\n{finding.evidence}"
    req = urllib.request.Request(webhook, data=json.dumps({"text": text}).encode(),
                                 headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception:
        pass  # alert delivery must never crash the watcher


async def run_forever(store: Store, poll_seconds: int = 60):
    """Check each watch when its own interval has elapsed."""
    import asyncio
    while True:
        now = time.time()
        for watch in store.all_watches():
            if now - (watch.get("last_checked_at") or 0) < watch["interval_seconds"]:
                continue
            try:
                await check_watch(store, watch)
            except Exception as e:
                store.log_alert(watch["id"], "medium", f"watcher error: {e}")
        await asyncio.sleep(poll_seconds)
