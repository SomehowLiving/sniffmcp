"""The CI path: `fleet --no-launch --format sarif` on a committed .mcp.json."""
import json
from pathlib import Path

from sniffmcp.cli import main

CONFIG = Path(__file__).parent / "fixtures" / "action" / ".mcp.json"


def test_no_launch_fleet_sarif_annotates_config_lines(tmp_path, monkeypatch):
    monkeypatch.setenv("SNIFFMCP_OFFLINE", "1")
    out = tmp_path / "r.sarif"
    # 'installer' would run `curl | sh` if launched; --no-launch must never start it
    code = main(["fleet", str(CONFIG), "--no-launch", "--format", "sarif", "--output", str(out)])
    assert code == 1                                   # SM-10 curl|sh is high
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
    assert {"SM-10", "SM-07", "SM-02"} <= ids
    assert "memory" not in by_server or all(r["ruleId"] != "SM-07" for r in by_server["memory"])
    assert "plaintext-token-for-tests-only" not in out.read_text()   # secrets redacted
