"""End to end over real stdio: spawn a server, handshake, scan, watch, detect drift."""
import json, os, sys
from pathlib import Path

from mcp_audit import watcher
from mcp_audit.engine import scan
from mcp_audit.state import Store

FIXTURE = str(Path(__file__).parent / "fixtures" / "fixture_server.py")


def cfg(mode):
    return {"command": sys.executable, "args": [FIXTURE], "env": {"FIXTURE_MODE": mode}, "timeout": 30}


async def test_scan_clean_fixture_over_stdio():
    report, manifest = await scan(cfg("clean"))
    assert {t["name"] for t in manifest["tools"]} == {"summarize", "format_text", "delete_note"}
    assert report.grade in ("A", "B"), [(f.severity, f.title) for f in report.findings]


async def test_scan_poisoned_fixture_over_stdio():
    report, _ = await scan(cfg("poisoned"))
    crit = [f for f in report.findings if f.severity == "critical"]
    assert any("text.description" in f.evidence for f in crit)


async def test_watch_detects_rug_pull(tmp_path):
    store = Store(str(tmp_path / "state.db"))
    store.add_watch("notes", cfg("clean"), "stdio", 0)
    assert await watcher.check_watch(store, store.get_watch("notes")) == []   # baseline
    assert await watcher.check_watch(store, store.get_watch("notes")) == []   # unchanged

    # the server updates itself
    store.add_watch("notes", cfg("rugpull"), "stdio", 0)
    findings = await watcher.check_watch(store, store.get_watch("notes"))
    assert any(f.severity == "critical" and f.tool_name == "summarize" for f in findings)
    assert any(f.tool_name == "run_command" and f.kind == "risky" for f in findings)
    n_alerts = len(store.alerts())

    await watcher.check_watch(store, store.get_watch("notes"))   # same bad version again
    assert len(store.alerts()) == n_alerts                       # alert once, not every poll

    assert await watcher.accept(store, "notes")
    assert await watcher.check_watch(store, store.get_watch("notes")) == []


async def test_unreachable_server_is_a_connect_error():
    from mcp_audit.client import ConnectError
    try:
        await scan({"command": "definitely-not-a-real-binary-xyz", "timeout": 10})
    except ConnectError as e:
        assert "definitely-not-a-real-binary-xyz" in str(e) or "No such file" in str(e) or e
    else:
        raise AssertionError("expected ConnectError")
