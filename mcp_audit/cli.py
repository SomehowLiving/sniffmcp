"""mcp-audit CLI. Same engine as the MCP server.

Exit contract (stable):
  0  scan completed, no active finding at/above --fail-on
  1  scan completed, at least one active finding at/above threshold
  2  target or configuration error
  3  analysis incomplete (server unreachable / timed out)

Usage:
  mcp-audit scan '{"command":"npx","args":["-y","pkg@1.2.3"]}'
  mcp-audit scan https://mcp.example.com/mcp
  mcp-audit scan cfg.json --format sarif --output results.sarif
  mcp-audit fleet                      # every server in your Claude/Cursor/Windsurf configs
  mcp-audit watch cfg.json --name myserver --webhook https://hooks.slack.com/...
  mcp-audit watch --name myserver --accept     # accept the current manifest as the new baseline
  mcp-audit watch --run                        # check all watches on their intervals, forever
  mcp-audit crawl run --output crawl-report.md # daily: registry sync, probe public servers, package history
"""
from __future__ import annotations
import argparse, asyncio, json, os, sys
from pathlib import Path

from .client import ConnectError, transport_of
from .engine import scan
from .scoring import summarize
from .report import to_sarif, fleet_to_sarif, to_json_report, diff_baseline, apply_suppressions, gate, SEVERITY_RANK
from .state import Store
from . import watcher
from .fleet import scan_fleet, fleet_console


def load_config(arg: str) -> dict:
    """Inline JSON, a path to a JSON file, or an http(s) URL."""
    arg = arg.strip()
    if arg.startswith(("https://", "http://")):
        return {"url": arg}
    if arg.startswith("{"):
        return json.loads(arg)
    return json.loads(Path(arg).read_text())


def console_print(report) -> None:
    print(f"\n  {report.target}\n  score {report.score}/100  grade {report.grade}  ({report.tool_count} tools)")
    s = summarize(report.findings)
    print(f"  critical:{s['critical']} high:{s['high']} medium:{s['medium']} low:{s['low']} info:{s['info']}")
    for f in sorted(report.findings, key=lambda f: -SEVERITY_RANK.get(f.severity, 0)):
        mark = " (suppressed)" if f.suppressed else ""
        print(f"  [{f.severity:8}] {f.check_id:8} {f.title}{mark}")
        if f.evidence and f.severity != "info":
            print(f"             {f.evidence[:150]}")


async def cmd_scan(args) -> int:
    try:
        config = load_config(args.config)
    except Exception as e:
        print(f"error: config must be JSON, a JSON file path, or a URL ({e})", file=sys.stderr)
        return 2
    try:
        report, _ = await scan(config, launch=not args.no_launch)
    except ConnectError as e:
        print(f"error: {e}", file=sys.stderr)
        return 3
    findings = report.findings
    apply_suppressions(findings, Path(args.suppress).read_text() if args.suppress else "", args.suppress)
    if args.baseline:
        try:
            diff_baseline(findings, json.loads(Path(args.baseline).read_text()))
        except Exception as e:
            print(f"warning: baseline ignored ({e})", file=sys.stderr)

    if args.format == "sarif":
        out = json.dumps(to_sarif(findings, report.target), indent=2)
    elif args.format == "json":
        out = json.dumps(to_json_report(report.target, report.score, report.grade, findings,
                                        report.manifest_hash), indent=2)
    else:
        console_print(report)
        out = None
    if out and args.output:
        Path(args.output).write_text(out)
        print(f"wrote {args.output}")
    elif out:
        print(out)
    return gate(findings, args.fail_on)


async def cmd_watch(args) -> int:
    store = Store()
    if args.run:
        print("watching all servers; Ctrl+C to stop")
        await watcher.run_forever(store)
        return 0
    if not args.name:
        print("error: --name is required", file=sys.stderr)
        return 2
    if args.accept:
        try:
            ok = await watcher.accept(store, args.name)
        except ConnectError as e:
            print(f"error: {e}", file=sys.stderr)
            return 3
        print(f"baseline for '{args.name}' updated" if ok else f"no watch named '{args.name}'")
        return 0 if ok else 2
    if args.config:
        try:
            config = load_config(args.config)
        except Exception as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        store.add_watch(args.name, config, transport_of(config), args.interval, args.webhook)
    watch = store.get_watch(args.name)
    if not watch:
        print(f"error: no watch named '{args.name}'; pass a config to create it", file=sys.stderr)
        return 2
    had_baseline = bool(watch.get("baseline_hash"))
    findings = await watcher.check_watch(store, watch)
    if not had_baseline and store.get_watch(args.name).get("baseline_hash"):
        print(f"baseline set for '{args.name}'")
    elif not findings:
        print(f"'{args.name}': no changes since baseline")
    for f in findings:
        print(f"  [{f.severity:8}] [{f.kind or '-':8}] {f.title}")
        if f.evidence:
            print(f"             {f.evidence[:150]}")
    return gate(findings, "high")


async def cmd_crawl(args) -> int:
    from . import crawler
    from .crawldb import CrawlDB
    db = CrawlDB(args.db)

    def progress(done, total, what, status):
        if status != "ok" or done % 50 == 0 or done == total:
            print(f"  [{done}/{total}] {status:8} {what[:90]}", file=sys.stderr)

    if args.action in ("sync", "run"):
        print(f"sync: {await crawler.sync_registry(db)}", file=sys.stderr)
    if args.action in ("probe", "run"):
        print(f"probe: {await crawler.probe_remotes(db, concurrency=args.concurrency, min_age_h=args.min_age, limit=args.limit, per_host_cap=args.per_host_cap, progress=progress)}",
              file=sys.stderr)
    if args.action in ("packages", "run"):
        print(f"packages: {await crawler.crawl_packages(db, concurrency=args.concurrency, min_age_h=args.min_age, limit=args.limit, progress=progress)}",
              file=sys.stderr)
    if args.action in ("advisories", "run"):
        print(f"advisories: {await crawler.crawl_advisories(db)}", file=sys.stderr)
    if args.action == "rescore":
        print(f"rescored {crawler.rescore(db)} snapshots with the current rules", file=sys.stderr)
    if args.action in ("report", "run", "rescore"):
        md = crawler.report(db, days=args.days)
        if args.output:
            Path(args.output).write_text(md)
            print(f"wrote {args.output}", file=sys.stderr)
        else:
            print(md)
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="mcp-audit")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan one MCP server")
    s.add_argument("config", help="inline JSON, path to a JSON file, or an MCP URL")
    s.add_argument("--format", choices=["console", "json", "sarif"], default="console")
    s.add_argument("--output", default=None)
    s.add_argument("--fail-on", default="high", choices=list(SEVERITY_RANK.keys()))
    s.add_argument("--baseline", default=None, help="previous JSON report; matched findings don't gate")
    s.add_argument("--suppress", default=None, help="suppressions file (directives or JSON rules)")
    s.add_argument("--offline", action="store_true", help="skip OSV malware/vulnerability lookups")
    s.add_argument("--no-launch", action="store_true", help="never start a stdio server: config + OSV checks only")

    wch = sub.add_parser("watch", help="baseline a server and report post-install changes")
    wch.add_argument("config", nargs="?", help="config to create/update the watch")
    wch.add_argument("--name")
    wch.add_argument("--interval", type=int, default=3600)
    wch.add_argument("--webhook", default=None)
    wch.add_argument("--accept", action="store_true", help="accept the current manifest as the baseline")
    wch.add_argument("--run", action="store_true", help="check every watch on its interval, forever")

    fl = sub.add_parser("fleet", help="scan every installed MCP server from client configs")
    fl.add_argument("paths", nargs="*", help="config file paths; omit to auto-discover")
    fl.add_argument("--format", choices=["console", "json", "sarif"], default="console")
    fl.add_argument("--output", default=None)
    fl.add_argument("--fail-on", default="high", choices=list(SEVERITY_RANK.keys()))
    fl.add_argument("--offline", action="store_true", help="skip OSV malware/vulnerability lookups")
    fl.add_argument("--no-launch", action="store_true",
                    help="never start stdio servers: config + OSV checks only (use in CI on untrusted configs)")

    cr = sub.add_parser("crawl", help="crawl the official MCP registry and snapshot public servers over time")
    cr.add_argument("action", choices=["sync", "probe", "packages", "advisories", "report", "run", "rescore"],
                    help="run = sync + probe + packages + advisories + report (what a daily cron should call)")
    cr.add_argument("--db", default=None, help="crawl database (default ~/.mcp_audit/crawl.db)")
    cr.add_argument("--limit", type=int, default=None, help="probe/check at most N items")
    cr.add_argument("--concurrency", type=int, default=8)
    cr.add_argument("--min-age", type=float, default=20, help="hours before an item is re-probed")
    cr.add_argument("--per-host-cap", type=int, default=100, help="max endpoints probed per host per run (rotates)")
    cr.add_argument("--days", type=int, default=7, help="report window")
    cr.add_argument("--output", default=None, help="write the report here instead of stdout")

    sv = sub.add_parser("serve", help="run as an MCP server")
    sv.add_argument("--http", action="store_true")
    sv.add_argument("--port", type=int, default=8930)

    args = ap.parse_args(argv)
    if getattr(args, "offline", False):
        os.environ["MCP_AUDIT_OFFLINE"] = "1"
    if args.cmd == "fleet":
        try:
            fleet = asyncio.run(scan_fleet(args.paths or None, args.fail_on, launch=not args.no_launch))
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        if args.format in ("json", "sarif"):
            out = json.dumps(fleet if args.format == "json" else fleet_to_sarif(fleet), indent=2)
            if args.output:
                Path(args.output).write_text(out)
                print(f"wrote {args.output}")
            else:
                print(out)
        else:
            fleet_console(fleet)
        return fleet["summary"]["gate"]
    if args.cmd == "scan":
        return asyncio.run(cmd_scan(args))
    if args.cmd == "watch":
        return asyncio.run(cmd_watch(args))
    if args.cmd == "crawl":
        return asyncio.run(cmd_crawl(args))
    if args.cmd == "serve":
        from .server import mcp   # mcp.run() owns its event loop; don't wrap it in asyncio.run
        if args.http:
            mcp.run(transport="streamable-http", host="127.0.0.1", port=args.port)
        else:
            mcp.run(transport="stdio")
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
