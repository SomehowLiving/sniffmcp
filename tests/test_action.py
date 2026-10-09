"""The CI path: `fleet --no-launch --format sarif` on a committed .mcp.json."""
import json
from pathlib import Path

from mcp_audit.cli import main

CONFIG = Path(__file__).parent / "fixtures" / "action" / ".mcp.json"


def test_no_launch_fleet_sarif_annotates_config_lines(tmp_path, monkeypatch):
    monkeypatch.setenv("MCP_AUDIT_OFFLINE", "1")
    out = tmp_path / "r.sarif"
    # 'installer' would run `curl | sh` if launched; --no-launch must never start it
    code = main(["fleet", str(CONFIG), "--no-launch", "--format", "sarif", "--output", str(out)])
    assert code == 1                                   # MA-10 curl|sh is high
    run = json.loads(out.read_text())["runs"][0]
    assert not run["invocations"][0]["toolExecutionNotifications"]   # nothing unreachable: nothing spawned
    by_server = {}
    for r in run["results"]:
        by_server.setdefault(r["properties"]["server"], []).append(r)
    lines = CONFIG.read_text().splitlines()
    for server, results in by_server.items():
        loc = results[0]["locations"][0]["physicalLocation"]
        assert loc["artifactLocation"]["uri"].endswith(".mcp.json")
        assert f'"{server}"' in lines[loc["region"]["startLine"] - 1]
    ids = {r["ruleId"] for r in run["results"]}
    assert {"MA-10", "MA-07", "MA-02"} <= ids
    assert "memory" not in by_server or all(r["ruleId"] != "MA-07" for r in by_server["memory"])
    assert "plaintext-token-for-tests-only" not in out.read_text()   # secrets redacted
