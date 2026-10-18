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
   risky and capability changes go to the webhook, whatever their severity.
4. After you review, `--accept` makes the current version the baseline.

State lives in `~/.sniffmcp/state.db`.

## Pin everything, gate what matters

The obvious defence against rug pulls is to hash each tool at approval and refuse any call whose hash
has moved. SniffMCP does pin the full surface, but the crawl data shows why *blocking on every change*
backfires:

- **Versions don't tell you.** In the Oct 9–12 crawl, 73% of tool-definition changes came with no bump
  in either the registry version or the server's own `serverInfo.version`. Pinning a version number
  doesn't pin what the model reads; you have to hash the definitions themselves.
- **Changes are frequent.** About 3.6% of public servers changed their definitions on a given night.
  With ~10 servers installed, that's roughly a 31% chance per night that at least one changed, or a
  re-approval prompt every ~3 days. (A rough estimate: it assumes servers change independently, and in
  reality a few busy servers change far more often than most.)
- **Most changes are harmless.** Of the 1,939 changes on Oct 10, 70% were wording edits and 28% were
  breaking (a removed tool or a new required parameter).

If every one of those needs a human to approve it, people stop reading the prompts, and the gate stops
protecting anyone. So SniffMCP:

| Change class | What SniffMCP does | What a client should do |
|---|---|---|
| **risky** (new injection indicator, a tool now claiming to be read-only, a new off-site URL) | alert | block until re-approved |
| **capability** (new delete / exec / secret-reading tool) | alert | block until re-approved |
| **breaking** (tool removed, new required parameter) | log | nothing: the call fails on its own; it's a reliability issue, not a safety one |
| **benign** (wording, own-site links, new harmless tool) | log | accept and log |

SniffMCP runs beside your client, not between the client and the server, so today it **alerts; it
doesn't block**. Two ways to close that gap are on the roadmap: a `--quarantine` option that disables a
server in your client config when a risky or capability change arrives, until you accept the diff
(effective from the next session), and later a proxy mode that can fail closed mid-session.

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
