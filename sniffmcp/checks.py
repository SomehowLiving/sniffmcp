"""Static checks over a server's config and manifest.

Check IDs (SM-01..SM-10) are sniffmcp's own and do not follow OWASP's numbering;
report.OWASP_FOR_CHECK maps each to the OWASP MCP Top 10 categories it covers.

Each check is a pure function: (context) -> list[Finding]. The context is a
ManifestContext built by the client after connecting to the target server.
Pure functions = unit-testable without any MCP transport.

Calibration rule: a popular, legitimate server must land at A/B. Findings
describe evidence that something is wrong; what a server is *able* to do
(write files, run commands) is reported at low/info so the user can decide,
not punished as if it were a defect. Tool *descriptions* are analysed in
injection.py (INJ-HEUR); this module covers config, transport, capabilities,
server instructions, prompts and drift.
"""
from __future__ import annotations
import difflib, os, re
from .models import Finding
from .injection import scan_text, tool_texts

# ---------- context ----------
class ManifestContext:
    def __init__(self, target, transport, config, tools, resources=None, prompts=None,
                 server_info=None, instructions=None, prior_manifest=None):
        self.target = target
        self.transport = transport
        self.config = config or {}          # raw server entry from client config
        self.tools = tools or []
        self.resources = resources or []
        self.prompts = prompts or []
        self.server_info = server_info or {}
        self.instructions = instructions or ""   # server-level instructions field
        self.prior_manifest = prior_manifest     # dict from state store, or None

# ---------- helpers ----------
SECRET_PATTERNS = [
    ("OpenAI/Anthropic-style key", re.compile(r"\bsk-(ant-)?[A-Za-z0-9_-]{20,}")),
    ("GitHub token",    re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}|\bgithub_pat_[A-Za-z0-9_]{40,}")),
    ("AWS access key",  re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("Slack token",     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("Stripe key",      re.compile(r"\b[rs]k_(live|test)_[A-Za-z0-9]{16,}")),
    ("Google API key",  re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("Bearer token",    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{24,}")),
    ("JWT",             re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("Private key PEM", re.compile(r"-----BEGIN ([A-Z]+ )?PRIVATE KEY-----")),
]
SENSITIVE_NAME = re.compile(r"(?i)(token|secret|password|passwd|api_?key|private_?key|credential|auth)")
ENV_REF = re.compile(r"^\$\{[^}]+\}$|^\$[A-Za-z_][A-Za-z0-9_]*$")
SENSITIVE_PATH = re.compile(   # concrete secret locations only; .env.example etc. are templates
    r"(?i)(\.ssh/|\bid_(rsa|ed25519|ecdsa)\b|\.aws/credentials|\.kube/config|\.netrc|"
    r"\.env(\.(local|production|prod|development|dev|staging))?(?=$|[?#\s\"'])|"
    r"\.git-credentials|\.docker/config\.json|/etc/shadow|\.pem$|\.p12$|keychain)")


def redact(value: str) -> str:
    """Never echo a secret into a report (reports end up in CI logs and SARIF uploads)."""
    value = str(value)
    return f"{value[:4]}…({len(value)} chars)" if len(value) > 4 else "****"


def find_secrets(text):
    hits = []
    for label, rx in SECRET_PATTERNS:
        for m in rx.finditer(text or ""):
            hits.append((label, redact(m.group(0))))
    return hits


def name_tokens(name: str) -> set[str]:
    """'deleteFile' / 'delete_file' / 'delete-file' -> {'delete', 'file'}."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name or "")
    return {t.lower() for t in re.split(r"[^A-Za-z0-9]+", spaced) if t}


DESTRUCTIVE = {"delete", "remove", "rm", "rmdir", "drop", "truncate", "destroy", "wipe", "purge",
               "erase", "kill", "terminate", "unlink", "revoke", "reset", "overwrite"}
WRITE = {"write", "create", "update", "edit", "modify", "set", "put", "patch", "insert", "upsert",
         "move", "rename", "push", "merge", "send", "post", "publish", "upload", "deploy",
         "commit", "close", "archive", "add", "fork", "transfer", "pay", "charge", "refund"}
EXEC = {"exec", "shell", "eval", "bash", "terminal", "spawn", "subprocess", "powershell"}
SENSITIVE_TOOL = {"env", "environ", "environment", "credential", "credentials", "secret", "secrets",
                  "password", "passwords", "passwd", "keychain", "keyring", "vault", "ssh",
                  "apikey", "privatekey"}


def tool_capability(tool: dict) -> set[str]:
    toks = name_tokens(tool.get("name", ""))
    caps = set()
    if toks & DESTRUCTIVE:
        caps.add("destructive")
    if toks & WRITE:
        caps.add("write")
    # "execute"/"run" alone is often a namespace (execute_read_portfolio, seen in the wild)
    if toks & EXEC or (toks & {"run", "invoke", "execute"}
                       and toks & {"code", "command", "commands", "cmd", "script", "python", "js", "process", "sql"}):
        caps.add("exec")
    if toks & SENSITIVE_TOOL:
        caps.add("sensitive")
    return caps


def _short_list(names, n=6):
    names = list(names)
    return ", ".join(names[:n]) + (f" (+{len(names) - n} more)" if len(names) > n else "")

# ---------- checks (IDs are frozen; see report.RULES_META and report.OWASP_FOR_CHECK) ----------

def check_tool_poisoning(ctx: ManifestContext) -> list[Finding]:
    """SM-01: server-level instructions carrying hidden directives.
    (Tool descriptions and parameter descriptions: injection.analyze_descriptions.)"""
    out = []
    for label, sev, snippet in scan_text(ctx.instructions):
        out.append(Finding("SM-01", sev, f"Server instructions: {label}", f"…{snippet}…",
            "Server instructions are injected into every session. Review them; never let them override user intent."))
    return out


def check_token_mismanagement(ctx: ManifestContext) -> list[Finding]:
    """SM-02: credentials stored in plaintext in the server entry."""
    out = []
    args = " ".join(str(a) for a in ctx.config.get("args") or [])
    for label, snip in find_secrets(args):
        out.append(Finding("SM-02", "high", f"{label} passed as a command-line argument", snip,
            "Arguments are visible to every local process (ps, /proc). Pass it via env or an OAuth flow."))
    url = str(ctx.config.get("url", ""))
    if re.search(r"(?i)[?&](api_?key|token|key|secret|access_token)=[^&]{8,}", url):
        out.append(Finding("SM-02", "high", "Credential in remote server URL query string",
            re.sub(r"=([^&]{4})[^&]*", r"=\1…", url),
            "URLs end up in proxy and server logs. Send credentials in a header or use OAuth."))
    for k, v in (ctx.config.get("env") or {}).items():
        v = str(v)
        if ENV_REF.match(v.strip()):
            continue  # ${VAR} reference: the secret lives outside the config file
        if SENSITIVE_NAME.search(k) and len(v) >= 8 or find_secrets(v):
            out.append(Finding("SM-02", "medium", f"Plaintext credential in config env '{k}'", redact(v),
                "Any process (or any other MCP server with file access) that can read this config can read the key. "
                "Reference it as ${VAR} from your shell environment, or use OAuth.", ))
    for k, v in (ctx.config.get("headers") or {}).items():
        v = str(v)
        if not ENV_REF.search(v.split()[-1] if v.split() else v) and (SENSITIVE_NAME.search(k) or find_secrets(v)):
            out.append(Finding("SM-02", "medium", f"Plaintext credential in config header '{k}'", redact(v),
                "Reference it as ${VAR} instead of storing it in the config file."))
    return out


def _drift_text_added(old: str, new: str) -> str:
    sm = difflib.SequenceMatcher(None, old, new)
    return " ".join(new[j1:j2] for op, _, _, j1, j2 in sm.get_opcodes() if op in ("insert", "replace"))


def _required(tool: dict) -> set[str]:
    return set((tool.get("inputSchema") or {}).get("required") or [])


def _site(host: str) -> str:
    parts = host.lower().rstrip(".").split(".")
    return ".".join(parts[-3:]) if len(parts) > 2 and len(parts[-2]) <= 3 else ".".join(parts[-2:])


def _same_site(url: str, server_url: str | None) -> bool:
    """Same registrable domain (roughly): docs/privacy links on a server's own site are benign.
    Shared hosting (workers.dev, vercel.app, ...) counts as different on purpose."""
    from urllib.parse import urlparse
    if not server_url:
        return False
    a, b = urlparse(url).hostname or "", urlparse(server_url).hostname or ""
    shared = ("workers.dev", "vercel.app", "netlify.app", "pages.dev", "herokuapp.com", "github.io",
              "supabase.co", "onrender.com", "fly.dev", "railway.app")
    if any(a.endswith(s) or b.endswith(s) for s in shared):
        return a == b
    return bool(a) and _site(a) == _site(b)


def _drift_severity(hits) -> str:
    """A change is as serious as the indicator it introduced: a new critical/high indicator pages
    you (critical); a new medium hint ("before calling other tools", seen 2026-10-16 in a reworded
    usage note) is a medium risky change for the weekly review, not a page."""
    sevs = {h[1] for h in hits}
    return "critical" if sevs & {"critical", "high"} else "medium" if "medium" in sevs else "low"


def check_rug_pull(ctx: ManifestContext) -> list[Finding]:
    """SM-03: drift vs a stored baseline, classified so benign updates don't page anyone.
      risky      -> new injection indicators; a tool *relaxing* to read-only / non-destructive
                    (clients may start auto-approving it); new URLs pointing off the server's domain
      capability -> new delete/exec/secret-reading tools, a tool now declaring itself destructive
                    (normal product growth, but your agent's blast radius changed)
      breaking   -> tool removed, required parameter added (breaks skills/workflows)
      benign     -> wording changes, new harmless tools, links to the server's own domain
    Calibrated on the 2026-10-10 crawl: 27 "risky" under the old rules, 0 attacks."""
    out = []
    if not ctx.prior_manifest:
        return [Finding("SM-03", "info", "No baseline stored — first scan", "",
            "Run `sniffmcp watch` to baseline this server and detect post-install changes.")]
    prior = {t.get("name"): t for t in ctx.prior_manifest.get("tools", [])}
    now = {t.get("name"): t for t in ctx.tools}

    for name in sorted(now.keys() - prior.keys()):
        t = now[name]
        hits = [h for _, text in tool_texts(t) for h in scan_text(text)]
        caps = tool_capability(t) & {"destructive", "exec", "sensitive"}
        if hits:
            out.append(Finding("SM-03", _drift_severity(hits), f"New tool '{name}' arrived with injection indicators",
                "; ".join(f"{l}: …{s}…" for l, _, s in hits[:3]),
                "This is the rug-pull pattern. Remove the server until reviewed.", tool_name=name, kind="risky"))
        elif caps:
            out.append(Finding("SM-03", "medium" if "exec" in caps else "low",
                f"New {'/'.join(sorted(caps))} tool '{name}' added after baseline",
                (t.get("description") or "")[:160],
                "Your agent can now do more through this server; keep manual approval on for it.",
                tool_name=name, kind="capability"))
        else:
            out.append(Finding("SM-03", "info", f"New tool '{name}' added", (t.get("description") or "")[:160],
                "Benign-looking addition.", tool_name=name, kind="benign"))

    for name in sorted(prior.keys() - now.keys()):
        out.append(Finding("SM-03", "low", f"Tool '{name}' removed", "Skills or workflows calling it will break.",
            "Check the server changelog.", tool_name=name, kind="breaking"))

    for name in sorted(prior.keys() & now.keys()):
        old, new = prior[name], now[name]
        old_texts, new_texts = dict(tool_texts(old)), dict(tool_texts(new))
        added = " ".join(_drift_text_added(old_texts.get(k, ""), v)
                         for k, v in new_texts.items() if v != old_texts.get(k, ""))
        new_hits = [h for h in scan_text(added) if h[0] not in {x[0] for t in old_texts.values() for x in scan_text(t)}]
        if new_hits:
            out.append(Finding("SM-03", _drift_severity(new_hits), f"Tool '{name}' metadata changed and gained injection indicators",
                "; ".join(f"{l}: …{s}…" for l, _, s in new_hits[:3]),
                "Description mutation after install is the Deadbugz pattern. Stop using this server and review.",
                tool_name=name, kind="risky"))
        elif added.strip():
            urls = re.findall(r"https?://[^\s)\"']+", added)
            foreign = [u for u in urls if not _same_site(u, ctx.config.get("url"))]
            if foreign:
                sev, kind, why = "medium", "risky", f"new off-site URL(s): {_short_list(foreign, 3)}"
            else:
                sev, kind, why = "info", "benign", ("new link(s) to its own site" if urls else "wording change")
            out.append(Finding("SM-03", sev, f"Tool '{name}' description changed",
                f"{why}; added text: {added.strip()[:160]}", "Review the diff.", tool_name=name, kind=kind))
        newly_required = _required(new) - _required(old)
        if newly_required:
            out.append(Finding("SM-03", "low", f"Tool '{name}' has new required parameter(s)",
                _short_list(sorted(newly_required)), "Existing callers will fail until updated.",
                tool_name=name, kind="breaking"))
        oa, na = old.get("annotations") or {}, new.get("annotations") or {}
        # Risky relaxation = a tool that *explicitly* said it writes/destroys now claims read-only,
        # or a write/delete/exec-named tool gains a read-only claim. A read-named tool getting its
        # first annotations ({} -> readOnlyHint) is servers improving (60 such on 2026-10-10).
        claims_ro = na.get("readOnlyHint") and not oa.get("readOnlyHint")
        claims_safe = oa.get("destructiveHint") and na.get("destructiveHint") is False
        explicit_before = oa.get("readOnlyHint") is False or oa.get("destructiveHint") is True
        # only unambiguous verbs: "post"/"set"/"add" are often nouns (read_x_post, get_settings)
        powerful_name = bool(tool_capability(new) & {"destructive", "exec"})
        relaxed = (claims_ro or claims_safe) and (explicit_before or powerful_name)
        tightened = (oa.get("readOnlyHint") and not na.get("readOnlyHint")) or \
                    (na.get("destructiveHint") and not oa.get("destructiveHint"))
        if relaxed:
            # high only for delete/exec-named tools; other relaxations are usually corrections
            # (a "Browse" tool fixing an over-cautious hint) and wait for the weekly review
            out.append(Finding("SM-03", "high" if powerful_name else "medium",
                f"Tool '{name}' now claims to be read-only / non-destructive",
                f"annotations {oa} -> {na}",
                "Clients may start auto-approving it. Check the tool still does what the new hint says.",
                tool_name=name, kind="risky"))
        elif tightened:
            out.append(Finding("SM-03", "low", f"Tool '{name}' now declares itself destructive / not read-only",
                f"annotations {oa} -> {na}",
                "More honest, but if you gave this tool an always-allow permission, review it.",
                tool_name=name, kind="capability"))
    return out


def check_excessive_privileges(ctx: ManifestContext) -> list[Finding]:
    """SM-04: what the server can do, plus annotations that lie about it.
    Clients use readOnlyHint to auto-approve calls, so a destructive tool that
    claims to be read-only is a real defect; merely having write tools is not."""
    out = []
    by_cap: dict[str, list[str]] = {"exec": [], "destructive": [], "write": []}
    for t in ctx.tools:
        name, caps = t.get("name", ""), tool_capability(t)
        for c in by_cap:
            if c in caps:
                by_cap[c].append(name)
        ann = t.get("annotations") or {}
        # Names are weak evidence: real read-only tools are called diagnose_sales_drop,
        # list_wipe_jobs, execute_sql_readonly. Only a name that *starts* with a strong
        # destructive verb contradicts readOnlyHint, and even then it's "check", not "lie".
        first = re.split(r"[^a-z0-9]+", re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name).lower())[0]
        if ann.get("readOnlyHint") and first in {"delete", "drop", "destroy", "wipe", "truncate", "purge", "erase", "rm"}:
            out.append(Finding("SM-04", "medium", f"Tool '{name}' claims readOnlyHint but its name starts with '{first}'",
                f"annotations: {ann}",
                "Clients may auto-approve read-only tools. Check what it does before auto-approving.",
                tool_name=name))
        elif "destructive" in caps and ann.get("destructiveHint") is False:
            out.append(Finding("SM-04", "medium", f"Tool '{name}' declares destructiveHint=false",
                f"annotations: {ann}", "Require manual approval for this tool regardless of its hint.", tool_name=name))
    if by_cap["exec"]:
        out.append(Finding("SM-04", "medium", "Can execute commands or code on the host",
            _short_list(by_cap["exec"]),
            "Keep manual approval on for these tools; run the server in a container if you can."))
    if by_cap["destructive"]:
        out.append(Finding("SM-04", "low", "Has destructive tools", _short_list(by_cap["destructive"]),
            "Keep manual approval on for these tools."))
    if by_cap["write"]:
        out.append(Finding("SM-04", "info", f"Has {len(by_cap['write'])} write-capable tool(s)",
            _short_list(by_cap["write"]), "Scope the server's credentials to what you need."))
    return out


def check_sensitive_data_scope(ctx: ManifestContext) -> list[Finding]:
    """SM-05: tools and resources aimed at secrets, env, keychains."""
    out = []
    names = [t.get("name") for t in ctx.tools if "sensitive" in tool_capability(t)]
    if names:
        out.append(Finding("SM-05", "medium", "Tools that read secrets, credentials or environment",
            _short_list(names), "Make sure their output can't be forwarded by another tool (e.g. a web fetch or message send)."))
    for r in ctx.resources:
        uri = str(r.get("uri", ""))
        if SENSITIVE_PATH.search(uri):
            out.append(Finding("SM-05", "high", "Resource URI points at a sensitive path", uri,
                "Do not expose credential-bearing resources to the agent; remove or gate them."))
    return out


LOCAL_HOSTS = re.compile(r"^http://(localhost|127\.\d+\.\d+\.\d+|\[::1\]|0\.0\.0\.0)(:\d+)?(/|$)")


def check_transport_security(ctx: ManifestContext) -> list[Finding]:
    """SM-06: cleartext remote transport."""
    out = []
    url = str(ctx.config.get("url", ""))
    if url.startswith("http://") and not LOCAL_HOSTS.match(url):
        has_creds = bool(ctx.config.get("headers"))
        out.append(Finding("SM-06", "critical" if has_creds else "high",
            "Remote MCP server over plain HTTP" + (" with credentials in headers" if has_creds else ""), url,
            "Tool schemas, results and any credentials travel in cleartext. Use https."))
    elif url and ctx.transport != "stdio" and not ctx.config.get("headers") and not ctx.config.get("_oauth"):
        out.append(Finding("SM-06", "info", "Remote server with no client credentials configured", url,
            "Fine for public read-only servers; if the client does OAuth, this is expected."))
    return out


NPM_RUNNERS = {"npx", "bunx", "pnpx"}
PY_RUNNERS = {"uvx"}
DOCKER_VALUE_FLAGS = {"-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "--network", "-w",
                      "--workdir", "--env-file", "--mount", "-u", "--user", "--entrypoint", "--platform",
                      "-l", "--label", "--add-host", "--cpus", "-m", "--memory"}
NPM_PINNED = re.compile(r"^(@[^/@]+/)?[^@/]+@v?\d+\.\d+\.\d+([-+][\w.]+)?$")
PY_PINNED = re.compile(r"(==|@)v?\d+(\.\d+)+([-+.\w]*)$|@[0-9a-f]{7,40}$")


def launch_spec(config: dict) -> tuple[str, str] | None:
    """(ecosystem, package spec) for servers launched through a package runner."""
    cmd = os.path.basename(str(config.get("command") or "")).removesuffix(".cmd").removesuffix(".exe")
    args = [str(a) for a in config.get("args") or []]
    if cmd in ("npm", "pnpm", "yarn") and args[:1] in (["exec"], ["dlx"]):
        cmd, args = "npx", args[1:]
    if cmd == "pipx" and args[:1] == ["run"]:
        cmd, args = "uvx", args[1:]
    if cmd == "uv" and args[:2] == ["tool", "run"]:
        cmd, args = "uvx", args[2:]
    if cmd in NPM_RUNNERS:
        for i, a in enumerate(args):
            if a in ("-p", "--package") and i + 1 < len(args):
                return "npm", args[i + 1]
            if a.startswith("--package="):
                return "npm", a.split("=", 1)[1]
        pos = [a for a in args if not a.startswith("-")]
        return ("npm", pos[0]) if pos else None
    if cmd in PY_RUNNERS:
        for i, a in enumerate(args):
            if a == "--from" and i + 1 < len(args):
                return "pypi", args[i + 1]
        pos, skip = [], False
        for a in args:
            if skip:
                skip = False
            elif a in ("--python", "--with", "--index-url", "-p", "-w"):
                skip = True
            elif not a.startswith("-"):
                pos.append(a)
        return ("pypi", pos[0]) if pos else None
    if cmd in ("docker", "podman") and "run" in args:
        rest, skip = args[args.index("run") + 1:], False
        for a in rest:
            if skip:
                skip = False
            elif a in DOCKER_VALUE_FLAGS:
                skip = True
            elif not a.startswith("-"):
                return "docker", a
    return None


def check_unpinned_dependencies(ctx: ManifestContext) -> list[Finding]:
    """SM-07: server fetched from a registry at launch without an exact version."""
    spec = launch_spec(ctx.config)
    if not spec:
        return []
    eco, pkg = spec
    fix = "Pin an exact version so a malicious or broken publish can't reach you silently."
    if eco == "npm" and not NPM_PINNED.match(pkg):
        return [Finding("SM-07", "medium", "npm package launched without an exact version", pkg,
                        fix + " e.g. npx -y pkg@1.2.3")]
    if eco == "pypi" and not PY_PINNED.search(pkg) and not pkg.startswith(("/", ".")):
        return [Finding("SM-07", "medium", "Python package launched without an exact version", pkg,
                        fix + " e.g. uvx pkg==1.2.3")]
    if eco == "docker":
        if "@sha256:" in pkg:
            return []
        tag = pkg.rsplit("/", 1)[-1].partition(":")[2]
        if not tag or tag == "latest":
            return [Finding("SM-07", "medium", "Container image without a tag or digest", pkg,
                            fix + " Use image@sha256:<digest>.")]
        return [Finding("SM-07", "info", "Container image pinned by tag (tags are mutable)", pkg,
                        "Pin by digest for full reproducibility.")]
    return []


def check_attack_surface(ctx: ManifestContext) -> list[Finding]:
    """SM-08: very large tool sets, duplicate names."""
    out = []
    n = len(ctx.tools)
    if n > 40:
        chars = sum(len(str(t.get("description", ""))) + len(str(t.get("inputSchema", ""))) for t in ctx.tools)
        out.append(Finding("SM-08", "low", f"Large tool surface ({n} tools)",
            f"~{chars // 4:,} tokens of tool definitions",
            "Disable the tools you don't use; each one is context cost and another injection surface."))
    names = [t.get("name", "") for t in ctx.tools]
    dups = sorted({x for x in names if names.count(x) > 1})
    if dups:
        out.append(Finding("SM-08", "high", "Duplicate tool names", ", ".join(dups),
            "Duplicate names can shadow a legitimate tool with a malicious twin."))
    return out


def check_resource_exposure(ctx: ManifestContext) -> list[Finding]:
    """SM-09: prompts carrying hidden directives (prompts are instructions surfaced to the model)."""
    out = []
    for p in ctx.prompts:
        texts = [p.get("description") or ""] + [a.get("description") or "" for a in p.get("arguments") or []]
        for label, sev, snippet in (h for t in texts for h in scan_text(t, user_invoked=True)):
            out.append(Finding("SM-09", sev, f"Prompt '{p.get('name')}': {label}", f"…{snippet}…",
                "Prompts are executable instructions surfaced to the model; treat like tool descriptions."))
    return out


PIPE_TO_SHELL = re.compile(r"(?i)(curl|wget|iwr|invoke-webrequest)\b[^|]*\|\s*(sh|bash|zsh|python3?|iex|node)\b|\biex\s*\(")
TLS_OFF = {"NODE_TLS_REJECT_UNAUTHORIZED": "0", "PYTHONHTTPSVERIFY": "0"}


def check_config_hygiene(ctx: ManifestContext) -> list[Finding]:
    """SM-10: dangerous launch configuration."""
    out = []
    cmdline = " ".join([str(ctx.config.get("command") or "")] + [str(a) for a in ctx.config.get("args") or []])
    if PIPE_TO_SHELL.search(cmdline):
        out.append(Finding("SM-10", "high", "Launch command downloads and executes a script", cmdline[:160],
            "Every launch runs whatever that URL serves today. Install a pinned package instead."))
    for k, bad in TLS_OFF.items():
        if str((ctx.config.get("env") or {}).get(k, "")) == bad:
            out.append(Finding("SM-10", "medium", f"TLS verification disabled ({k}={bad})", k,
                "Remove it; the server's outbound traffic can be intercepted."))
    return out


ALL_CHECKS = [check_tool_poisoning, check_token_mismanagement, check_rug_pull,
              check_excessive_privileges, check_sensitive_data_scope,
              check_transport_security, check_unpinned_dependencies,
              check_attack_surface, check_resource_exposure, check_config_hygiene]


def run_all_checks(ctx: ManifestContext) -> list[Finding]:
    findings = []
    for c in ALL_CHECKS:
        try:
            findings.extend(c(ctx))
        except Exception as e:  # a broken check must never kill the scan
            findings.append(Finding(c.__name__, "info", f"check errored: {e}", "", ""))
    return findings
