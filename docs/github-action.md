# GitHub Action

Teams commit MCP configs to their repos: `.mcp.json` (Claude Code project servers) and
`.cursor/mcp.json`. The action audits them on every pull request and shows findings on the exact line
of the config in code scanning.

```yaml
name: sniffmcp
on: [pull_request, push]
permissions:
  contents: read
  security-events: write   # for the code scanning upload
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: SomehowLiving/sniffmcp@v0.5.1
        with:
          config: .mcp.json .cursor/mcp.json
          fail-on: high
```

## Safe by default

By default the action **does not start any server** (`launch: false`). A pull request could add a
server whose command *is* the attack, and the runner would execute it. Without launching, the action
still:

- checks configs for plaintext secrets, unpinned packages, `curl | sh` launches, plain HTTP and
  disabled TLS verification;
- looks up every package in OSV for known malware and vulnerabilities;
- connects to remote (URL) servers and runs the full set of description checks.

Only set `launch: "true"` for configs you trust, for example on pushes to your default branch.

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `config` | `.mcp.json` | Config file(s) to audit, space-separated |
| `fail-on` | `high` | Fail the job on findings at or above this severity |
| `launch` | `false` | Start stdio servers to inspect their tools (runs their commands) |
| `offline` | `false` | Skip OSV malware/vulnerability lookups |
| `fail-on-unreachable` | `false` | Fail when a server can't be analysed (e.g. behind OAuth) |
| `sarif-file` | `sniffmcp.sarif` | Where to write the SARIF report |
| `upload-sarif` | `true` | Upload the SARIF to code scanning (needs `security-events: write`) |

## Outputs

| Output | Meaning |
|---|---|
| `sarif-file` | Path of the SARIF report |
| `exit-code` | `0` clean, `1` findings at/above `fail-on`, `2` bad config, `3` some servers not analysed |

The action also writes a summary table to the job summary page.

## Without the action

Any CI can run the CLI directly:

```bash
uvx sniffmcp-cli fleet .mcp.json --no-launch --format sarif --output sniffmcp.sarif --fail-on high
```
