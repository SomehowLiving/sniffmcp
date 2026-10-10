"""Fleet scanning: audit every MCP server a user has installed, in one pass.

Config sources:
  - Claude Desktop: claude_desktop_config.json  ({"mcpServers": {...}})
  - Claude Code:    ~/.claude.json  (user-scope "mcpServers" and per-project
                    "projects.<path>.mcpServers"), plus ./.mcp.json
  - Cursor:         ~/.cursor/mcp.json
  - Windsurf:       ~/.codeium/windsurf/mcp_config.json
  - Any JSON file with an "mcpServers" object, or a bare {name: config} map

Scanning a stdio entry runs its command, exactly as your client does on
startup. Per-server failures never abort the fleet scan — one dead server must
not hide the other fourteen.
"""
from __future__ import annotations
import asyncio, json, os, re, sys
from pathlib import Path

from .client import ConnectError
from .engine import scan
from .models import Finding
from .report import to_json_report, gate, SEVERITY_RANK
from .injection import scan_text, tool_texts

CONFIG_CANDIDATES = [
    ("claude-desktop", "~/Library/Application Support/Claude/claude_desktop_config.json"),
    ("claude-desktop", "~/.config/Claude/claude_desktop_config.json"),
    ("claude-desktop", "~/AppData/Roaming/Claude/claude_desktop_config.json"),
    ("cursor",         "~/.cursor/mcp.json"),
    ("claude-code",    "~/.claude.json"),
    ("claude-code",    "./.mcp.json"),
    ("windsurf",       "~/.codeium/windsurf/mcp_config.json"),
]


def discover_config_paths() -> list[str]:
    found = []
    for _label, p in CONFIG_CANDIDATES:
        pp = Path(os.path.expanduser(p)).resolve()
        if pp.exists() and str(pp) not in found:
            found.append(str(pp))
    return found


def _servers_in(block) -> dict[str, dict]:
    if not isinstance(block, dict):
        return {}
    return {name: cfg for name, cfg in block.items()
            if isinstance(cfg, dict) and ("command" in cfg or "url" in cfg)}


def load_servers(path: str) -> dict[str, dict]:
    raw = json.loads(Path(path).read_text())
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: not a JSON object")
    servers = _servers_in(raw.get("mcpServers")) if "mcpServers" in raw else {}
    # Claude Code keeps project-scoped servers under projects.<path>.mcpServers
    for proj, block in (raw.get("projects") or {}).items():
        for name, cfg in _servers_in((block or {}).get("mcpServers")).items():
            servers.setdefault(f"{name} ({Path(proj).name})", cfg)
    if not servers and "mcpServers" not in raw and "projects" not in raw:
        servers = _servers_in(raw)   # bare {name: config} map
    return servers


async def scan_one(name: str, config: dict, fail_on: str = "high", launch: bool = True,
                   auth: str = "stored") -> dict:
    try:
        report, manifest = await scan(config, launch=launch, auth=auth)
    except ConnectError as e:
        return {"name": name, "target": config.get("url") or config.get("command", "?"),
                "status": "error", "error": str(e)}
    out = to_json_report(report.target, report.score, report.grade, report.findings, report.manifest_hash)
    texts = [(t.get("name"), where, x) for t in manifest.get("tools", []) for where, x in tool_texts(t) if x]
    if manifest.get("instructions"):
        texts.append((None, "server instructions", manifest["instructions"]))
    texts += [(None, f"prompt {p.get('name')}", p.get("description") or "") for p in manifest.get("prompts") or []]
    out.update(name=name, transport=report.transport, status="ok", tool_count=report.tool_count,
               tool_names=[t.get("name") for t in manifest.get("tools", [])], _texts=texts,
               gate=gate(report.findings, fail_on))
    return out


def tool_collisions(results: list[dict]) -> list[Finding]:
    """The same tool name exposed by two servers: the agent picks one, and a
    malicious server can shadow a trusted one this way."""
    owners: dict[str, list[str]] = {}
    for r in results:
        for t in r.get("tool_names") or []:
            owners.setdefault(t, []).append(r["name"])
    return [Finding("FLEET-01", "medium", f"Tool name '{t}' exposed by {len(s)} servers", ", ".join(s),
                    "Remove one, or check which server your client actually routes this name to.", tool_name=t)
            for t, s in sorted(owners.items()) if len(s) > 1]


_DISTINCTIVE = re.compile(r"^(?=.{6,}$)[A-Za-z][A-Za-z0-9]*([_-][A-Za-z0-9]+)+$|^[a-z]+[A-Z][A-Za-z0-9]{3,}$")


def cross_server_references(results: list[dict]) -> list[tuple[str, dict]]:
    """Shadowing in Invariant's sense: one server's model-visible text names a tool that
    belongs to ANOTHER installed server ("when you call send_email, also BCC ..."). That's how
    a malicious server hijacks a trusted one. Only distinctive names (snake/kebab/camelCase,
    6+ chars) count, so ordinary words like "search" don't."""
    owner: dict[str, set[str]] = {}
    for r in results:
        for t in r.get("tool_names") or []:
            if t and _DISTINCTIVE.match(t):
                owner.setdefault(t, set()).add(r["name"])
    out = []
    for r in results:
        own = set(r.get("tool_names") or [])
        for tool, where, text in r.get("_texts") or []:
            for name, servers in owner.items():
                others = servers - {r["name"]}
                if not others or name in own:
                    continue
                m = re.search(rf"(?<![\w-]){re.escape(name)}(?![\w-])", text)
                if not m:
                    continue
                window = text[max(0, m.start() - 150): m.end() + 150]
                directive = [h for h in scan_text(window) if h[0] in ("cross-tool instruction", "exfiltration directive",
                                                                    "instruction override", "concealment from user")]
                directive = directive or re.search(r"(?i)\b(always|also|instead|before|after|must|bcc|cc|forward|redirect)\b", window)
                sev = "high" if directive else "medium"
                out.append((r["name"], {
                    "check_id": "FLEET-02", "severity": sev,
                    "title": f"References another server's tool '{name}' ({', '.join(sorted(others))})",
                    "evidence": f"{where}{f' of {tool}' if tool else ''}: …{' '.join(window.split())[:220]}…",
                    "remediation": "A server telling the agent how to use another server's tools is the shadowing "
                                   "attack. Check why this server mentions it; remove it if you can't explain it.",
                    "tool_name": tool, "kind": "", "owasp_mcp": ["MCP03"], "suppressed": False}))
    return out


async def scan_fleet(paths: list[str] | None = None, fail_on: str = "high", launch: bool = True,
                     login: bool = False) -> dict:
    if not paths:
        paths = discover_config_paths()
    if not paths:
        raise ValueError("no config files found; pass paths explicitly")

    servers: dict[str, dict] = {}
    sources: dict[str, str] = {}
    warnings = []
    for p in paths:
        try:
            for name, cfg in load_servers(p).items():
                servers.setdefault(name, cfg)   # first definition wins
                sources.setdefault(name, p)
        except Exception as e:
            warnings.append(f"skipping {p}: {e}")

    sem = asyncio.Semaphore(4)  # don't fork-bomb the user's machine
    async def bounded(name, cfg):
        async with sem:
            r = await scan_one(name, cfg, fail_on, launch)
            r["source"] = sources.get(name, "")
            return r
    results = await asyncio.gather(*[bounded(n, c) for n, c in servers.items()])
    # Parallel cold starts (several `npx -y` downloads at once) can time out on a
    # first run. Retry those one at a time; the package cache is warm by now.
    for i, r in enumerate(results):
        if r["status"] == "error" and "timed out" in r["error"] and "command" in servers[r["name"]]:
            retry = await scan_one(r["name"], servers[r["name"]], fail_on, launch)
            retry["source"] = r["source"]
            results[i] = retry
    # --login: one browser login at a time for servers that asked for OAuth
    if login:
        for i, r in enumerate(results):
            if r["status"] == "error" and "sniffmcp login" in r["error"]:
                print(f"\n  {r['name']} needs a login.", file=sys.stderr)
                retry = await scan_one(r["name"], servers[r["name"]], fail_on, launch, auth="interactive")
                retry["source"] = r["source"]
                results[i] = retry

    ok = [r for r in results if r["status"] == "ok"]
    errs = [r for r in results if r["status"] == "error"]
    scores = [r["score"] for r in ok]
    # one injection pattern across several servers is a bigger story than isolated lows
    freq: dict[str, int] = {}
    for r in ok:
        for cid in {f["check_id"] for f in r["findings"] if not f.get("suppressed")
                    and f["severity"] in ("critical", "high")}:
            freq[cid] = freq.get(cid, 0) + 1
    collisions = tool_collisions(ok)
    shadowing = cross_server_references(ok)
    by_name = {r["name"]: r for r in ok}
    for name, f in shadowing:
        by_name[name]["findings"].append(f)
        if SEVERITY_RANK[f["severity"]] >= SEVERITY_RANK[fail_on]:
            by_name[name]["gate"] = 1
    for r in ok:
        r.pop("_texts", None)

    summary = {
        "scanned": len(ok), "failed": len(errs), "total": len(results),
        "avg_score": round(sum(scores) / len(scores), 1) if scores else None,
        "grade_distribution": {g: sum(1 for r in ok if r["grade"] == g) for g in "ABCDF"},
        "servers_at_or_below_C": [r["name"] for r in ok if r["grade"] in ("C", "D", "F")],
        "high_or_critical_by_check": dict(sorted(freq.items(), key=lambda kv: -kv[1])),
        "tool_name_collisions": [{"tool": f.tool_name, "servers": f.evidence} for f in collisions],
        "cross_server_references": [{"server": n, "severity": f["severity"], "title": f["title"]} for n, f in shadowing],
        "worst": sorted(((r["name"], r["score"]) for r in ok), key=lambda x: x[1])[:5],
        # exit contract: 1 = findings at/above threshold, 3 = some servers not analysed, 0 = clean
        "gate": 1 if any(r.get("gate") == 1 for r in ok) else (3 if errs else 0),
        "warnings": warnings,
    }
    return {"summary": summary, "servers": results, "fail_on": fail_on}


def fleet_console(fleet: dict) -> None:
    s = fleet["summary"]
    print(f"\nFLEET: {s['scanned']}/{s['total']} servers scanned ({s['failed']} unreachable)")
    print(f"avg score {s['avg_score']}  grades {s['grade_distribution']}")
    for r in sorted((r for r in fleet["servers"] if r["status"] == "ok"), key=lambda r: r["score"]):
        flagged = [f for f in r["findings"] if f["severity"] in ("critical", "high") and not f.get("suppressed")]
        print(f"  {r['score']:3}/100 {r['grade']}  {r['name']}  ({r['tool_count']} tools)")
        for f in flagged[:5]:
            print(f"           [{f['severity']}] {f['title']}")
    for x in s.get("cross_server_references", []):
        print(f"  [shadowing:{x['severity']}] {x['server']}: {x['title']}")
    for c in s["tool_name_collisions"]:
        print(f"  [collision] tool '{c['tool']}' in: {c['servers']}")
    for r in fleet["servers"]:
        if r["status"] == "error":
            print(f"  [error] {r['name']}: {r['error'][:200]}")
    if any("sniffmcp login" in r.get("error", "") for r in fleet["servers"]):
        print("  tip: `sniffmcp fleet --login` logs in to each of these once; later scans reuse the login")
    for w in s["warnings"]:
        print(f"  [warning] {w}")


def fleet_markdown(fleet: dict, title: str = "sniffmcp") -> str:
    """Compact Markdown for a CI job summary."""
    s = fleet["summary"]
    L = [f"### {title}", "",
         f"{s['scanned']}/{s['total']} MCP servers analysed"
         + (f", {s['failed']} not reachable" if s["failed"] else "") + "", "",
         "| server | grade | high / critical findings |", "|---|---|---|"]
    for r in sorted(fleet["servers"], key=lambda r: r.get("score", -1)):
        if r["status"] != "ok":
            L.append(f"| `{r['name']}` | – | not analysed: {r['error'][:80]} |")
            continue
        bad = [f"{f['check_id']} {f['title']}" for f in r["findings"]
               if f["severity"] in ("critical", "high") and not f.get("suppressed")]
        L.append(f"| `{r['name']}` | {r['grade']} ({r['score']}) | {'<br>'.join(bad[:4]) or '—'} |")
    for x in s.get("cross_server_references", []):
        print(f"  [shadowing:{x['severity']}] {x['server']}: {x['title']}")
    for c in s["tool_name_collisions"]:
        L.append(f"\nTool name `{c['tool']}` is exposed by several servers: {c['servers']}")
    return "\n".join(L)
