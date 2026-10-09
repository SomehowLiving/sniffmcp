# Changelog

## 0.2.0 — 2026-10-09

First working release.

### Added
- Scanner over stdio, Streamable HTTP and SSE on the official MCP SDK 2.x (legacy
  `initialize` and 2026-07-28 `server/discover`).
- `fleet`: auto-discovers Claude Code (incl. per-project servers), Claude Desktop, Cursor,
  Windsurf and `.mcp.json`; detects tool-name collisions across servers (FLEET-01).
- Injection rules over descriptions, titles, every nested parameter description, prompts and
  server instructions, tuned against 10,409 live registry servers.
- **OSV.dev integration**: MA-11 known malware (blocks launching the package), MA-12 known
  vulnerabilities.
- Classified drift (risky / breaking / benign) for `watch`, alerting once per change, plus
  `--accept`.
- MCP server mode, with launch restrictions against prompt-injected command execution.
- Ecosystem crawler: registry sync, remote probes with an SSRF guard, npm/PyPI release
  signals, OSV advisories, reports, rescore.
- OWASP MCP Top 10 mapping on every finding (JSON and SARIF).
- SARIF 2.1.0, baselines, reason-bearing suppressions, stable exit codes.
- `scripts/benchmark_yara.py`: head-to-head with Cisco's YARA rules.

### Changed
- Check IDs renamed `MCP-xx` → `MA-xx` so they can't be confused with OWASP's `MCP01`–`MCP10`
  (report schema 2.0.0).
