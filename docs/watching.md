# Watching for changes (rug pulls)

An MCP server can change what it tells your agent at any time after you approve it: a new tool, a
reworded description, a new hidden instruction. Most changes are harmless product updates. SniffMCP's
job is to stay quiet about those and speak up about the few that aren't.

## How it works

```bash
sniffmcp watch cfg.json --name memory --webhook https://hooks.slack.com/...   # baseline + watch
sniffmcp watch --run                     # check every watch on its interval (default 3600 s)
sniffmcp watch --name memory --accept    # accept the current version as the new baseline
```

1. The first check stores a **baseline**: the full tool list, resources, prompts and instructions,
   plus a hash.
2. Every interval, SniffMCP lists the server again. If the hash matches, nothing happens.
3. If it differs, each change is **classified** (below). Alerts for a given version are sent once;
   critical and high ones go to the webhook.
4. After you review, `--accept` makes the current version the baseline.

State lives in `~/.sniffmcp/state.db`.

## Classification

| Class | What triggers it | Severity |
|---|---|---|
| **risky** | New or changed text gains an injection indicator (see [detection.md](detection.md)) | critical |
| **risky** | A tool that said it writes or deletes (or has a delete/exec name) now claims to be read-only or non-destructive. Clients may start auto-approving it | high for delete/exec-named tools, else medium |
| **risky** | A description gains a URL pointing off the server's own site | medium |
| **capability** | A new delete, exec or secret-reading tool; a tool now declaring itself destructive | low to medium |
| **breaking** | A tool removed; a new required parameter | low |
| **benign** | Wording changes, new harmless tools, links to the server's own site, a read-named tool getting its first annotations | info |

"Capability" isn't an accusation. Servers grow, and a new delete tool is normal, but it changes what
your agent can do, so it's worth knowing about.

## Calibration

The classes were tuned on real data. On the second day of the ecosystem crawl (2026-10-10), 405 of
11,370 servers changed overnight, producing 1,939 individual changes. The first version of the rules
called 27 of them risky; none was an attack. After calibration: 1,369 benign, 544 breaking,
23 capability, 3 risky. The main fixes were treating first-time annotations as servers improving
rather than relaxing, and only counting off-site URLs.

## What polling can't catch

A server that behaves differently *inside* a session (for example, turning malicious after a number
of tool calls) shows its clean face to every fresh connection, so a watcher won't see it. Catching
that needs a proxy that sits in the live session, which is on the roadmap.
