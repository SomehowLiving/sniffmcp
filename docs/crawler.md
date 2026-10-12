# The ecosystem crawler: method and data

Besides scanning your own servers, SniffMCP keeps a daily record of the public MCP ecosystem: every
server in the [official MCP registry](https://registry.modelcontextprotocol.io), what each remote one
tells agents, how that changes day to day, and what happens to the npm/PyPI packages they ship.

This page explains exactly how the data is collected, so any number we publish can be checked.

## What it measures

| Stage | What it does |
|---|---|
| `sync` | Reads the registry (`/v0/servers`, latest versions). Daily runs fetch only entries updated since the last sync (`updated_since`); a full re-read runs weekly |
| `probe` | Connects to each public remote endpoint and lists tools, resources, prompts and server instructions. Stores a full snapshot only when something changed, and classifies each change ([watching.md](watching.md)) |
| `packages` | npm/PyPI release history from metadata: install scripts appearing, provenance or trusted publishing dropped, a first release by a new publisher without provenance, source-only releases |
| `advisories` | Every tracked package against OSV: malware in any version, vulnerabilities in the current latest |
| `report` | A Markdown summary of the latest state |
| `rescore` | Re-grades every stored snapshot after a rule change, so numbers never mix old and new rules |

```bash
sniffmcp crawl run          # sync + probe + packages + advisories + report
sniffmcp crawl status       # health, days covered, gaps, recent runs
sniffmcp crawl digest       # what changed in the last day (used for email alerts)
```

## Rules the crawler keeps

- **List calls only.** It never calls a tool.
- **Public addresses only.** Registry entries are untrusted input; nothing that resolves to loopback,
  a LAN range or cloud metadata is contacted (SSRF guard).
- **Polite.** At most one probe per endpoint per 20 hours, two at a time per host, and 100 per host per
  run (bulk publishers with thousands of entries on one host are sampled in rotation).
- **No credentials.** Endpoints whose registry entry declares a required auth header are probed
  without one. If they answer 401/403 they are re-checked weekly instead of daily. Your stored OAuth
  logins are never used.
- **Packages are never downloaded or executed.** Metadata only.
- **Facts, not verdicts.** The database stores what was served and what changed. Findings are leads
  until a human has checked them.

## Definitions

| Term | Meaning |
|---|---|
| Endpoint | A remote URL from a registry entry. Templated URLs (`https://{tenant}.example/mcp`) are recorded but not probed |
| Answers without auth | The MCP handshake and list calls succeed without credentials |
| Requires auth | The server answers 401/403 |
| Error | Anything else: HTTP errors (most often 404), non-MCP responses, DNS failures |
| Change | A difference between two consecutive snapshots of one endpoint |

## Numbers (2026-10-11)

| | |
|---|---|
| Registry endpoints | 27,164 (285 templated, not probed) |
| Probed so far | 23,036 |
| Answer without auth | 13,014 (56%) |
| Require auth (401/403) | 6,446 (28%) |
| Declare required auth in the registry but answered without it | 936 of 2,514 probed (37%) |
| Packages tracked | npm 10,526 · PyPI 4,155 |

An independent crawler, [mcp-transparency-log](https://github.com/yassinht/mcp-transparency-log),
measured 56.8% of endpoints answering without auth on the same day with a different method.

**Read these carefully.** "Answers without auth" is not a vulnerability: many servers are public by
design. And a declared auth header that turns out optional is usually a free tier, not a bug; it does
mean registry metadata doesn't always match reality.

## Why it runs daily

npm deletes malicious versions after a takedown, and the evidence goes with them. On 2026-10-09, OSV
listed past malware in four packages shipped by registry servers (three from Shai-Hulud worm
variants). Only a crawler that runs *during* an incident records what was there. Changes are also only
datable to the day if no day is missed, so the crawl runs at a fixed time each day.

## Run your own

The crawl runs anywhere Python does; the database is a single SQLite file (`~/.sniffmcp/crawl.db`).

**On GitHub Actions, without a laptop:** `scripts/github-crawl.yml` is a workflow template for a
private repository you own.

- It runs the crawl daily and stores each day's database as a release (zstd-compressed, last 14 kept).
- It needs no access token; the built-in `GITHUB_TOKEN` is enough.
- Failed runs email you.

The reference dataset is collected this way. GitHub's scheduler can skip runs under load, so give the
schedule a backup slot that skips itself when the day's crawl already succeeded.

**On a laptop:** `scripts/daily-crawl.sh` crawls only when the last successful crawl is over 20 hours
old, so a machine that slept catches up instead of losing the day.

```cron
*/30 * * * * SNIFFMCP_BACKUP_DIR=/path/to/backups /path/to/sniffmcp/scripts/daily-crawl.sh
@reboot sleep 180 && /path/to/sniffmcp/scripts/daily-crawl.sh
```

On WSL, cron only runs while WSL is open: `scripts/windows-task.xml` is a Task Scheduler template, and
`scripts/notify-windows.sh` shows a Windows notification when a crawl fails or goes stale.

## Disclosure

Findings about specific servers are reported privately to their maintainers first and are not
published with names without permission. See [SECURITY.md](../SECURITY.md).
