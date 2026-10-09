# sniffmcp architecture

*As of 2026-10-09. See [README.md](README.md) for what it does and how to use it.*

## 1. The big picture

sniffmcp has three entry points and one shared engine. Everything that grades a server goes through the same pipeline, so the CLI, the watcher, the MCP server mode and the crawler always agree.

```mermaid
flowchart LR
    subgraph Entry["Entry points"]
        CLI["CLI<br/>scan · fleet · watch · crawl"]
        SRV["MCP server mode<br/>agent calls sniffmcp"]
        CRON["Daily cron<br/>crawl run"]
    end

    subgraph Core["Shared engine"]
        CLIENT["client.py<br/>connect + list"]
        ENGINE["engine.py<br/>one scan pipeline"]
        CHECKS["checks.py<br/>SM-01..10, drift"]
        INJ["injection.py<br/>text rules"]
        SCORE["scoring.py<br/>score + grade caps"]
        REPORT["report.py<br/>JSON · SARIF · OWASP map"]
    end

    subgraph Stores["Local SQLite"]
        STATE[("state.db<br/>watches, baselines, alerts")]
        CRAWL[("crawl.db<br/>registry, snapshots, changes, packages")]
    end

    subgraph Outside["Outside world"]
        LOCAL["Your installed servers<br/>stdio / HTTP / SSE"]
        REG["Official MCP registry"]
        PUB["Public remote MCP servers"]
        NPM["npm + PyPI metadata"]
    end

    CLI --> ENGINE
    SRV --> ENGINE
    CRON --> CRAWLER["crawler.py"]
    ENGINE --> CLIENT --> LOCAL
    ENGINE --> CHECKS --> INJ
    ENGINE --> SCORE --> REPORT
    CLI --> WATCH["watcher.py"] --> STATE
    WATCH --> CLIENT
    CRAWLER --> REG
    CRAWLER --> CLIENT --> PUB
    CRAWLER --> NPM
    CRAWLER --> ENGINE
    CRAWLER --> CRAWL
```

## 2. What we're built on

| Layer | What we use | Why |
|---|---|---|
| Language | Python 3.11+ (venv runs 3.12) | The official MCP SDK is first-class in Python |
| MCP protocol | **Official `mcp` SDK 2.3** (`Client`, `stdio_client`, `streamable_http_client`, `sse_client`, `MCPServer`) | We never hand-roll the protocol. `Client(mode="auto")` speaks both the legacy `initialize` handshake and the 2026-07-28 `server/discover` |
| HTTP | `httpx2` (ships with the SDK) | Auth-error probing, registry and npm/PyPI calls |
| Async | `asyncio` / `anyio` | Parallel fleet scans and crawl probes with semaphores |
| Storage | `sqlite3` (stdlib), WAL mode | Zero-ops, single file, good enough for millions of rows |
| Detection | Pure-Python regex rules + capability tokenizer | Free, instant, deterministic, testable. No LLM required |
| Output | JSON, **SARIF 2.1.0**, Markdown | CI gates, GitHub code scanning, human reports |
| Tests | `pytest` + `pytest-asyncio`, a real stdio fixture server | Covers the full path, not just pure functions |
| Runtime deps | **Exactly one: `mcp`** | Small attack surface for a security tool |

## 3. Scanning one server

```mermaid
flowchart TD
    A["Config<br/>JSON / file / URL / installed name"] --> P{"npx / uvx package?"}
    P -->|yes| OSV["OSV.dev lookup<br/>MAL- malware · GHSA/CVE"]
    OSV -->|known malware| STOP["report F, never spawn"]
    OSV -->|otherwise| B{"transport?"}
    P -->|no| B
    B -->|command| C["stdio_client<br/>spawn process, capture stderr"]
    B -->|url| D["streamable_http_client"]
    B -->|type: sse| E["sse_client"]
    C & D & E --> F["Client mode=auto<br/>discover or initialize"]
    F -->|fails| G["ConnectError<br/>401 → 'requires authentication, OAuth'<br/>timeout → stderr tail"]
    F --> H["List only what the server advertises<br/>tools · resources · prompts · instructions<br/>paginated"]
    H --> I["Manifest"]
    I --> J["checks.py<br/>config · transport · capabilities · pinning · drift"]
    I --> K["injection.py<br/>every description, title, nested<br/>parameter description, prompt"]
    J & K --> L["Findings"]
    L --> M["scoring.py<br/>100 − weighted deductions<br/>max 2 per check<br/>critical → F, high → C at best"]
    M --> N["report.py<br/>console · JSON · SARIF<br/>+ OWASP MCP IDs, secrets redacted"]
    N --> O["Exit code<br/>0 clean · 1 findings · 2 bad config · 3 not analysed"]
```

### How a text rule decides

Precision over recall. Every rule must stay silent on ~30 real descriptions from the crawl that once fooled it.

```mermaid
flowchart LR
    T["Text the model will read"] --> R["Run each rule"]
    R --> F1{"Match is a mention?<br/>quoted, 'detects…', 'never allow… to'"}
    F1 -->|yes| X["ignore"]
    F1 -->|no| F2{"encoded payload?"}
    F2 -->|"hex / slash list / no case mix"| X
    F2 -->|real base64 shape| H["hit"]
    F1 -->|no, other rule| H
    T --> U{"hidden Unicode?"}
    U -->|"ZWNJ/ZWJ in Persian, Arabic,<br/>Indic or emoji text"| X
    U -->|otherwise| H
    H --> C{"≥2 independent serious hits<br/>in the same text?"}
    C -->|yes| CR["escalate to critical<br/>'multiple injection indicators'"]
    C -->|no| K["keep rule severity"]
```

## 4. Watching for changes (rug pulls)

```mermaid
sequenceDiagram
    participant U as You
    participant W as watcher.py
    participant S as MCP server
    participant DB as state.db
    participant H as Webhook (Slack)

    U->>W: sniffmcp watch cfg.json --name x
    W->>S: connect + list
    W->>DB: store baseline hash + full tools
    loop every interval_seconds
        W->>S: connect + list
        W->>DB: snapshot (only if hash changed)
        alt same as baseline
            W-->>W: nothing
        else changed
            W->>W: classify each change<br/>risky / breaking / benign
            alt first time this version is seen
                W->>DB: log alerts
                W->>H: push critical/high only
            else already alerted
                W-->>W: stay quiet
            end
        end
    end
    U->>W: --accept (after review)
    W->>DB: baseline = current version
```

**Classification:**

| Change | Class | Severity |
|---|---|---|
| New or changed text gains an injection indicator | risky | critical |
| New exec / destructive / secret-reading tool | risky | high |
| Description gains a URL | risky | medium |
| Tool turns from read-only to destructive (annotations) | risky | medium |
| Tool removed, new required parameter | breaking | low |
| Wording change, harmless new tool | benign | info |

## 5. MCP server mode: guarding against our own tool

A scanner that a model can tell to "scan `{"command": "rm -rf ~"}`" is a remote-code-execution hole. Target resolution is the guard:

```mermaid
flowchart TD
    T["target from the model"] --> A{"name of a server already<br/>in your client configs?"}
    A -->|yes| OK["scan it<br/>(you already run it)"]
    A -->|no| B{"https:// or http:// URL?"}
    B -->|yes| OK2["scan remote"]
    B -->|no| C{"JSON with url?"}
    C -->|yes| OK2
    C -->|"JSON with command"| D{"SNIFFMCP_ALLOW_COMMANDS=1?"}
    D -->|yes| OK3["spawn"]
    D -->|no| NO["refuse"]
```

The HTTP server mode binds to `127.0.0.1` only.

## 6. The ecosystem crawler

```mermaid
flowchart TD
    REG["Official registry<br/>registry.modelcontextprotocol.io<br/>paged, retry on 5xx"] --> SYNC["sync"]
    SYNC --> SV[("servers<br/>server_versions")]
    SYNC --> EP[("endpoints")]
    SYNC --> PK[("packages")]

    EP --> SKIP{"skip?"}
    SKIP -->|"templated URL"| R1["record only"]
    SKIP -->|"declares required auth"| R1
    SKIP -->|probeable| DUE["due list<br/>stalest first<br/>≤100 per host per run"]
    DUE --> GUARD{"resolves only to<br/>public IPs?"}
    GUARD -->|"no: localhost / LAN / metadata"| R2["skipped (SSRF guard)"]
    GUARD -->|yes| PROBE["list tools/resources/prompts<br/>≤2 per host, 16 total<br/>never calls a tool"]
    PROBE --> PR[("probes<br/>every attempt")]
    PROBE --> HCH{"manifest hash<br/>changed?"}
    HCH -->|no| DONE["done"]
    HCH -->|yes| SNAP[("snapshots<br/>full manifest + grade")]
    SNAP --> DRIFT["drift engine<br/>vs previous snapshot"]
    DRIFT --> CH[("changes<br/>risky / breaking / benign")]

    PK --> META["npm / PyPI JSON<br/>metadata only, nothing executed"]
    META --> PV[("package_versions")]
    META --> EV["release_events<br/>install script added · provenance dropped<br/>new publisher w/o provenance · source-only"]
    EV --> PE[("package_events")]

    SV & PR & SNAP & CH & PV & PE --> REP["report.md"]
```

### Crawl database

```mermaid
erDiagram
    servers ||--o{ server_versions : "has"
    servers ||--o{ endpoints : "declares"
    servers ||--o{ packages : "declares"
    endpoints ||--o{ probes : "every attempt"
    endpoints ||--o{ snapshots : "only on change"
    endpoints ||--o{ changes : "between snapshots"
    packages ||--o{ package_versions : "release history"
    packages ||--o{ package_events : "signals"

    servers {
        text name PK
        text version
        text status
        text raw
    }
    endpoints {
        int id PK
        text url
        text transport
        int auth_declared
        text skip_reason
    }
    probes {
        int endpoint_id
        real taken_at
        text status
        text manifest_hash
    }
    snapshots {
        int endpoint_id
        text manifest_hash
        text manifest
        int score
        text grade
        text findings
    }
    changes {
        int endpoint_id
        text kind
        text severity
        text title
    }
    package_versions {
        text name
        text version
        text publisher
        int provenance
        text install_scripts
    }
    package_events {
        text name
        text version
        text kind
        text severity
    }
```

## 7. Public standards and data: what we use, and what we don't yet

Which public standards, threat research and data feeds sniffmcp builds on, and which it doesn't yet.

| Source | Used? | How |
|---|---|---|
| **OWASP MCP Top 10** (beta, 2025) | ✅ as of today | Every finding is tagged with OWASP IDs in JSON and SARIF. **Caveat:** our own IDs (`SM-01`…) don't follow OWASP numbering; see the map below |
| **Invariant Labs tool-poisoning research** (the `<IMPORTANT>` / read `~/.cursor/mcp.json` proof of concept) | ✅ | It's a regression test; our rules must grade it F |
| **Deadbugz write-ups** (Pillar Security, CSA, 2026) | ✅ | Shaped the drift checks and the fixture's rug-pull mode. It's also why we document that polling can't catch session-gated payloads |
| **Official MCP registry** | ✅ | Source of the crawl |
| **npm provenance / trusted publishing, PyPI metadata** | ✅ | Package release signals |
| **MCP spec tool annotations** (`readOnlyHint`, `destructiveHint`) | ✅ | Annotation-vs-name contradictions and annotation drift |
| **OSV.dev malicious-package advisories** (`MAL-…`, OpenSSF malicious-packages feed) | ✅ | `SM-11`. The scanner checks the package **before spawning it** and refuses to launch known malware. The crawler checks every registry package (`crawl advisories`) |
| **CVE / GHSA / PYSEC advisories** | ✅ | `SM-12`, via the same OSV queries. Pinned versions are checked exactly; unpinned ones at today's latest (what `npx`/`uvx` would run) |
| **Cisco mcp-scanner YARA rules** (Apache-2.0) | ✅ as a **benchmark**, not a dependency | `scripts/benchmark_yara.py` fetches them at a pinned commit and runs them head-to-head with ours on the labelled corpus and all 10k crawled servers. Results: `reports/benchmark-cisco-yara-*.md`. One lead they surfaced that we missed became a new rule ("installs code into agent config") |
| **LLM-as-judge** | ❌ (hook exists: `analyze_descriptions(llm_hook=…)`) | Cisco and Snyk use one. Optional second opinion for ambiguous text |

### Our checks mapped to OWASP MCP Top 10

| OWASP | Category | Our checks | Coverage |
|---|---|---|---|
| MCP01 | Token Mismanagement & Secret Exposure | SM-02, SM-05 | 🟢 config secrets, redaction |
| MCP02 | Privilege Escalation via Scope Creep | SM-04 | 🟡 capabilities only; we can't see token scopes |
| MCP03 | Tool Poisoning | INJ-HEUR, SM-01, SM-03, SM-08, SM-09, FLEET-01 | 🟢 our strongest area |
| MCP04 | Supply Chain & Dependency Tampering | SM-07, SM-10, **SM-11 (malware), SM-12 (CVEs)**, crawler package signals | 🟢 pinning, provenance, OSV malware + vulnerabilities |
| MCP05 | Command Injection & Execution | SM-04 (flags exec tools) | 🔴 we can't see handler code |
| MCP06 | Intent Flow Subversion | INJ-HEUR, SM-01 | 🟡 text only |
| MCP07 | Insufficient AuthN/AuthZ | SM-06, crawler auth stats | 🟡 transport + auth presence |
| MCP08 | Lack of Audit & Telemetry | — | 🔴 out of scope for a scanner |
| MCP09 | Shadow MCP Servers | `fleet` discovery (inventory) | 🟡 lists what's installed; no org-wide view |
| MCP10 | Context Injection & Over-Sharing | SM-05 | 🟡 |

## 8. How our approach compares

| | **sniffmcp** | **Snyk Agent Scan** (ex-Invariant mcp-scan) | **Cisco mcp-scanner** (open source) | **MCP-Sentinel** | **MCP-Shield** (indie) |
|---|---|---|---|---|---|
| Scans | Installed servers, live | Installed servers, live | Servers / tools, live | Server **source code** | Installed servers |
| Detection | Regex rules tuned on 10k real servers | Hosted analysis + rules | YARA + LLM judge + Cisco AI Defense | AST, Semgrep, LLM, Docker probes | Rules |
| Account / upload | **None, fully local** | Snyk token; tool data sent to Snyk | Local YARA; LLM/API optional | OpenAI key for full value | Local |
| Drift / rug pull | **Classified** risky / breaking / benign, alert once | Hash pinning (alerts on any change) | Rug-pull detection claimed | CI baselines (findings) | — |
| Ecosystem dataset | **Daily crawl of the whole registry, with history** | Not public | No | No | No |
| Package supply chain | OSV malware + CVEs (pre-spawn block), provenance drop, install scripts, publisher change | Snyk platform | — | Provenance | Typosquats, CVEs |
| Sees handler behaviour | ❌ | ❌ | Partly (LLM over implementations) | ✅ (source + probes) | ❌ |
| OAuth servers | ❌ yet | ✅ (via client) | depends | n/a | ? |
| Maturity | Days old | Most mature, Snyk-backed | ~900 stars | v1.4 | small |

**Where we're genuinely better:**
- **Calibrated precision.** Our rules were tested against 10,409 real servers, with every high/critical hit checked by hand. We have the false-positive corpus to prove it. Nobody else publishes that.
- **Fully local, one dependency.**
- **Drift that doesn't cry wolf.**
- **The longitudinal registry dataset.**

**Where we're worse:**
- No LLM or semantic analysis.
- No source or behaviour analysis.
- No OAuth.
- No track record. *None* of these tools, including ours, publish independently audited detection rates.

**What would actually make us defensible:** the dataset plus the published false-positive and true-positive corpus. A public benchmark that every scanner can be measured against is something the others can't easily copy.

## 9. Design decisions worth knowing

1. **One pipeline (`engine.py`).** The three duplicated copies from the original code drifted apart; now there's one.
2. **List calls only, never `tools/call`.** Keeps scanning safe for the scanned server and for us.
3. **Snapshots on change, probes always.** Small database, honest availability stats.
4. **Grade caps.** A confirmed injection can never "pass" through weighted maths.
5. **Capabilities aren't defects.** Write or exec tools are reported, not punished, so legitimate servers stay A/B.
6. **Mentions aren't attacks.** Security tools quote attack phrases; we skip quoted, negated or "detects…" contexts.
7. **SSRF guard in the crawler.** Registry entries are untrusted input.
8. **Secrets never echoed.** Reports end up in CI logs and SARIF uploads.

## 10. Next technical steps

1. ~~OSV integration~~ ✅ done (`SM-11`, `SM-12`, pre-spawn malware block, `crawl advisories`).
2. ~~Rename our IDs~~ ✅ done (`MCP-xx` → `SM-xx`, report schema 2.0.0).
3. **Publish the corpus**: the real-world false positives plus known attacks as a benchmark set.
4. **OAuth** in `client.py` (the SDK has an OAuth client provider), so the 36% of auth-gated servers become scannable.
5. **Optional LLM judge** behind the existing hook, only for ambiguous hits.
6. **Session proxy** (later): the only way to catch Deadbugz-style payloads that change mid-session.

---
Sources: [OWASP MCP Top 10](https://owasp.org/www-project-mcp-top-10/) · [Nordic APIs guide](https://nordicapis.com/guide-to-the-owasp-mcp-top-10/) · [Cisco mcp-scanner](https://blogs.cisco.com/ai/securing-the-ai-agent-supply-chain-with-ciscos-open-source-mcp-scanner) · [Scanner comparison (AgenticWire)](https://www.agenticwire.news/article/mcp-security-scanners-comparison) · [Snyk Agent Scan (appsecsanta)](https://appsecsanta.com/mcp-scan) · [OSV malicious packages (OpenSSF)](https://openssf.org/?p=11003) · [Deadbugz (Pillar Security)](https://www.pillar.security/blog/deadbugz-currently-active-mcp-supply-chain-campaign)
