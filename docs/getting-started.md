# Getting started

SniffMCP checks the MCP servers your AI agent uses: it connects the way your client does, reads
everything the model would read (tool and parameter descriptions, prompts, resources, server
instructions) and reports what's risky. It runs locally; nothing is uploaded and no account is needed.

## Install

Requires Python 3.11+.

```bash
uvx sniffmcp-cli fleet          # run once without installing (needs uv)
pipx install sniffmcp-cli       # or install it: gives you the `sniffmcp` command
```

The PyPI package is `sniffmcp-cli`; the command and Python module are `sniffmcp`.

## Your first scan

Scan every server in your client configs (Claude Code, including per-project servers, Claude Desktop,
Cursor, Windsurf, and `.mcp.json` files):

```bash
sniffmcp fleet
```

Scan a single server, by URL, config JSON or file:

```bash
sniffmcp scan https://mcp.example.com/mcp
sniffmcp scan '{"command":"npx","args":["-y","@modelcontextprotocol/server-memory"]}'
sniffmcp scan path/to/config.json
```

> **Scanning a stdio server runs its command**, exactly as your client would at startup. SniffMCP
> checks the package against OSV first and refuses to launch known malware, but only scan configs
> you would run anyway. Use `--no-launch` to check a config without starting anything.

## Reading the output

```text
  npx -y @modelcontextprotocol/server-memory
  score 89/100  grade B  (9 tools)
  critical:0 high:0 medium:1 low:1 info:2
  [medium  ] SM-07    npm package launched without an exact version
             @modelcontextprotocol/server-memory
  [low     ] SM-04    Has destructive tools
             delete_entities, delete_observations, delete_relations
```

- **Score** starts at 100 and loses points per finding: critical 25, high 15, medium 8, low 3, and at
  most two findings count per check.
- **Grade caps:** any critical finding caps the grade at **F**, any high at **C**, whatever the score.
  A confirmed injection can't be averaged away.
- **Capabilities aren't defects.** A server that can delete files gets a low "has destructive tools"
  note so you keep approval on, not a bad grade.

Every finding has an ID (see [detection.md](detection.md)) and is also tagged with its
[OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) categories in JSON and SARIF output.

## Output formats and exit codes

```bash
sniffmcp fleet --format json --output report.json
sniffmcp fleet --format sarif --output results.sarif     # for GitHub code scanning
sniffmcp scan cfg.json --fail-on high                    # non-zero exit at/above a severity
sniffmcp scan cfg.json --baseline last.json --fail-on high   # only *new* findings fail
```

| Exit code | Meaning |
|---|---|
| 0 | No finding at or above `--fail-on` |
| 1 | At least one finding at or above `--fail-on` |
| 2 | Bad config |
| 3 | Some servers could not be analysed |

`--offline` skips the OSV lookups. Secrets found in configs are always redacted in output.

## Servers that need a login

About a quarter of public MCP servers require a login (28% of probed endpoints on 2026-10-11). For servers that use OAuth, log in once and later scans reuse it:

```bash
sniffmcp login https://mcp.example.com/mcp
sniffmcp fleet --login        # log in to each installed server that needs it
```

Details, scopes and token storage: [oauth.md](oauth.md).

## Watch a server for changes

A server can change what it tells your agent after you install it. Baseline it and get alerted on
risky changes only:

```bash
sniffmcp watch cfg.json --name memory --webhook https://hooks.slack.com/...
sniffmcp watch --run                  # check every watch on its interval
sniffmcp watch --name memory --accept # accept the current version after review
```

How changes are classified: [watching.md](watching.md).

## Use it inside your agent

SniffMCP is also an MCP server, so your agent can scan before trusting:

```bash
claude mcp add sniffmcp -- /path/to/sniffmcp/.venv/bin/python -m sniffmcp.server
```

Tools: `list_installed_servers`, `scan_server`, `score_server`, `scan_all_installed`,
`analyze_tool_descriptions`, `watch_server`, `list_watches`.

A model-callable "scan this command" tool would be a remote-code-execution hole, so in server mode a
target must be a server already in your configs or an https URL. Arbitrary commands need
`SNIFFMCP_ALLOW_COMMANDS=1`. HTTP mode binds to localhost only.

## In CI

Audit committed `.mcp.json` / `.cursor/mcp.json` files on every pull request: [github-action.md](github-action.md).
