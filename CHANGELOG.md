# Changelog

## 0.5.1 — unreleased

### Fixed
- OAuth login on WSL could fail with "127.0.0.1 refused to connect": the random callback port could
  land in a range Windows reserves (Hyper-V/WSL), which can never be forwarded from the Windows
  browser. Callback ports now come from 20000–32767, skip Windows' reserved ranges on WSL, and a
  stored login whose port is reserved re-registers on a new one. Also waits briefly for WSL's
  localhost forwarding before opening the browser.

## 0.5.0 — 2026-10-10

### Added
- **OAuth login** for servers that require it: `sniffmcp login`, `logout`, `logins`, and
  `fleet --login`. Uses the MCP SDK's OAuth 2.1 client (discovery, dynamic client registration,
  PKCE, refresh) with a one-shot loopback callback; tokens stored owner-only in `~/.sniffmcp/oauth/`.
  Stored logins are reused by `scan`, `fleet` and `watch`, never by the crawler or `--no-launch`.
- Auth errors now say exactly what to run (`sniffmcp login <url>`).
- Requests **read-only OAuth scopes** (a scanner only lists tools); `SNIFFMCP_OAUTH_SCOPE` overrides.
- Branded login pages with the SniffMCP raccoon (success and failure), self-contained and hardened
  (no scripts, escaped input, no referrer). A refused login no longer shows "login complete".

## 0.4.1 — 2026-10-09

### Changed
- PyPI distribution name is **`sniffmcp-cli`** (PyPI rejects `sniffmcp` as too similar to an
  unrelated existing project). The command `sniffmcp`, the module and the repo are unchanged;
  `sniffmcp-cli` is also installed as a command so `uvx sniffmcp-cli` works.

## 0.4.0 — 2026-10-09

### Changed
- **Renamed the project from `mcp-audit` to SniffMCP.** The old name was already used by an
  unrelated MCP security tool in the same category. Everything moves at once (no users yet,
  so no compatibility aliases):
  - package, CLI and GitHub repo: `sniffmcp`; Python module `sniffmcp`
  - check IDs `MA-xx` → `SM-xx` (report schema 3.0.0)
  - environment variables `MCP_AUDIT_*` → `SNIFFMCP_*`
  - data directory `~/.mcp_audit/` → `~/.sniffmcp/`
  - GitHub Action: `SomehowLiving/sniffmcp@v0.4.0`

## 0.3.0 — 2026-10-09

### Added
- **GitHub Action** (`action.yml`): audits committed MCP configs on pull requests, with a job
  summary table and SARIF annotations on the exact config line. Never launches servers by default.
- `--no-launch` for `scan` and `fleet`: config + OSV checks without starting stdio servers.
- `fleet --format sarif` with physical locations in the config file.

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
