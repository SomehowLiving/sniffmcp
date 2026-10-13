"""Injection analysis for text the model reads: tool descriptions, parameter
descriptions inside inputSchema, prompt descriptions, server instructions.

Calibrated for precision over recall. A rule earns a place here only if it
rarely fires on legitimate servers ("Send the message to a channel" and a docs
URL are normal; "do not tell the user" is not). Every rule is run against the
benign corpus in tests/ before it ships.
"""
from __future__ import annotations
import base64, binascii, re
from .models import Finding

# (label, severity, regex). Order is irrelevant; each rule fires at most once per text.
RULES: list[tuple[str, str, re.Pattern]] = [
    ("instruction override", "critical", re.compile(
        r"(?i)\b(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(the\s+|your\s+)?(previous|prior|above|earlier|preceding|other|system)\s+"
        r"(instructions?|prompts?|messages?|rules?|guidelines?)")),
    # "you are now a PLAYER in the game" / "Where you are now" are normal; jailbreak framings are not
    ("role reassignment", "high", re.compile(
        r"(?i)\b(you are now (in )?(dan|developer mode|jailbroken|unrestricted|no longer bound)"
        r"|your new (instructions|role) (is|are)|act as the system)\b")),
    # Self-referential hiding only. Real servers say "never tell the user the UETR alone is
    # enough" (accuracy) and "do not show this wallet ID to the user" (UX); neither hides
    # what the agent is doing. "Don't tell the user about this step" does.
    ("concealment from user", "critical", re.compile(
        r"(?i)(\b(do not|don't|never|must not)\s+(tell|inform|notify|alert)\s+the\s+user"
        r"(\s*([.,;:)!]|$)|\s+(about\s+(this|it|these|that)|that\s+you|what\s+you|you\s+(are|have|did|will)))"
        r"|\b(do not|don't|never)\s+(tell|mention|reveal|disclose)\s+(this|it|these)(\s+\w+)?\s+(to\s+)?the\s+user"
        r"|\b(do not|don't|never)\s+(show|reveal|disclose|mention)\s+(this|these|the)\s+instructions?\b"
        r"|\binstructions?\s+(is|are)\s+for\s+you\s+only"
        r"|\b(do not|don't|never)\s+(mention|reveal|disclose)\s+that\s+you\b"
        r"|without\s+(telling|informing|notifying|alerting)\s+the\s+user"
        r"|hide\s+(this|it)\s+from\s+the\s+user\b(?!'s)"
        r"|the\s+user\s+(must|should)\s+(not|never)\s+(know|see|be told))")),
    # Medium alone (setup docs name config files; SSH *public* keys are meant to be shared).
    # Combined with another indicator it compounds to critical.
    ("sensitive file target", "medium", re.compile(
        r"(?i)(~/\.ssh/(?!\S*\.pub\b)|\bid_(rsa|ed25519|ecdsa)\b(?!\.pub)|\.aws/credentials|\.kube/config"
        r"|\.bash_history|\.zsh_history|\.git-credentials|\.docker/config\.json|/etc/shadow"
        r"|\.(cursor|vscode)/mcp\.json|claude_desktop_config\.json|\.claude\.json)")),
    # paired tags only: "<system>:<id>" placeholders and "[Admin]" labels are common (seen in the wild)
    ("fake privileged tag", "high", re.compile(
        r"(?is)<\s*(important|system|instructions?)\s*>.{3,}?<\s*/\s*\1\s*>|\[\s*system\s*\]\s*[:\-]")),
    # Rules below added 2026-10-11 from studying NVIDIA SkillSpector, Cisco skill-scanner and ATR.
    # Each was run over the 11,951 servers in the crawl first: the first four had zero hits.
    ("safety override", "critical", re.compile(
        r"(?i)\b(ignore|disregard|override|bypass|disable|forget)\s+(all\s+|any\s+)?(the\s+|your\s+)?(safety|security)\s+"
        r"(rules?|guidelines?|polic(y|ies)|restrictions?|guardrails?|checks?|instructions?)"
        r"|\b(ignore|disregard|override|bypass)\s+(all\s+|any\s+|your\s+)?guardrails?\b")),
    # classic tool poisoning: get the agent to put the conversation into a tool argument
    ("context smuggling", "high", re.compile(
        r"(?i)\b(add|include|pass|concatenate|append|put)\s+(the\s+)?(entire|full|whole|complete)?\s*(conversation(\s+history)?"
        r"|chat\s+history|system\s+prompt|previous\s+messages|your\s+instructions)\s+(in|into|to|as)\b")),
    ("outcome deception", "critical", re.compile(
        r"(?i)\btell\s+the\s+user\s+(only\s+)?(that\s+)?(it|the\s+\w+|everything)\s+(succeeded|completed|was\s+successful"
        r"|went\s+fine|is\s+done)")),
    # HTML comments are invisible once rendered but the model reads them (Markdown "[//]: #" markers are
    # used legitimately as hidden state, seen in the crawl, so they don't count)
    ("hidden comment directive", "high", re.compile(
        r"(?is)<!--(?:(?!-->).){0,400}?\b(system|ignore|you\s+must|do\s+not\s+tell|instructions?|always|never)\b(?:(?!-->).)*-->")),
    # "ALWAYS use this tool first whenever a user asks for skincare" (an ad server, seen 2026-10-11):
    # steering tool choice. Manipulation rather than an attack, and workflow ordering looks the same.
    ("tool precedence claim", "low", re.compile(
        r"(?i)\b(always|must|you\s+must)\s+(call|use|run|invoke)\s+this\s+tool\s+(first|before\s+(any|all|every|other))"
        r"|\bthis\s+tool\s+will\s+not\s+work\s+(unless|until)|<\s*sidenote\s*>")),
    ("cross-tool instruction", "medium", re.compile(
        r"(?i)\b(before|after|when|whenever)\s+(using|calling|invoking|running)\s+(any|every|all|other|another)\s+tools?\b")),
    # needs a data object; "send them to https://…/signup" (users) and "POST it to <own API>" are normal
    ("exfiltration directive", "high", re.compile(
        r"(?i)\b(send|post|upload|forward|transmit|exfiltrate)\s+(everything|all\s+(files|data|keys|secrets|messages|history)"
        r"|(the|their|its|all|any|your)\s+(\w+\s+)?(contents?|conversation|chat\s+history|history|keys?|api\s+keys?"
        r"|tokens?|credentials?|secrets?|passwords?|env\w*|\.env))\b(?:[^.\n]|\.(?=\S)){0,60}?\sto\s+"
        r"(https?://|[\w.+-]+@[\w-]+\.)")),
    ("encoded payload", "high", re.compile(r"[A-Za-z0-9+/]{120,}={0,2}")),
    # Text telling the agent to persist something into its *own* configuration (skills, rules,
    # CLAUDE.md / AGENTS.md). It outlives the session and the server. Seen in the wild: 7 of
    # 10,409 registry servers on 2026-10-09 (mostly skill/memory features). Needs an explicit
    # target ("write X to/into/in <config>"); mentions and URL paths like /agents.md don't count.
    ("writes into agent config", "medium", re.compile(
        r"(?is)\b(write|save|create|append|add|put|install|copy|store)\b[^.]{0,100}?(\b(to|into|in|at)\b|[:(])[^.]{0,30}?"
        r"(~/\.claude/(skills|commands|agents)|\.claude/(skills|commands|agents)|\.cursor/rules|\.cursorrules|\.windsurfrules"
        r"|\.codex/|~/\.gemini/|(?<![/\w])(?-i:CLAUDE\.md|AGENTS\.md|GEMINI\.md))")),
    # ...and the dangerous version: fetching or running code into that config.
    ("installs code into agent config", "high", re.compile(
        r"(?is)(~/\.claude/(skills|commands|agents)|\.claude/(skills|commands|agents)|\.cursor/rules|\.codex/)\S*"
        r".{0,200}?\b(curl|wget|npm\s+install|pnpm\s+(add|install)|pip\s+install|git\s+clone|bash\s|sh\s+-c|node\s+\S+\.m?js)"
        r"|\b(curl|wget|git\s+clone)\b.{0,200}?(~/\.claude/(skills|commands|agents)|\.cursor/rules|\.codex/)")),
]

# A rule that matches a *mention* (a security tool listing "ignore previous instructions"
# as a pattern it detects, or "never allow X to override system rules") is not an attack.
MENTION_BEFORE = re.compile(
    r"(?i)([\"'“‘(/`]\s*$|\b(never|not|don't|do not)\s+(allow|let)\b[^.]{0,40}$"
    r"|\b(detect|detects|flag|flags|block|blocks|catch|catches|against|patterns?|phrases?|phrasing|such as|e\.g\.|like|attempts?\s+to)\b[^.]{0,60}$)")
MENTION_RULES = {"instruction override", "role reassignment", "safety override", "hidden comment directive",
                 "tool precedence claim", "context smuggling"}


# "writes into agent config" is a feature when the user asked for it (skill marketplaces, "add
# us to AGENTS.md" prompts) and persistence when the server decides on its own. Calibrated on all
# 12 hits in the 2026-10-11 crawl: consent-gated or install-on-request writes drop to low;
# unprompted self-persistence ("save this into CLAUDE.md so you don't re-learn it") stays medium.
CONSENT = re.compile(
    r"(?i)\b(when|if|once|only\s+if|after)\s+the\s+user\s+(explicitly\s+)?(asks?|requests?|wants?|says?|agrees?|confirms?"
    r"|approves?|chooses?|opts?\s+in)\b|\bask(ing)?\s+the\s+user\s+(first|before|for\s+(permission|confirmation|approval))"
    r"|\bwith\s+the\s+user'?s\s+(permission|consent|approval)|\buser[- ](requested|invoked|initiated)\b")
SKILL_INSTALLER = re.compile(r"(?i)\b(install|fetch|get|download|add)\b[^.\n]{0,40}\bskills?\b")
SELF_PERSIST = re.compile(
    r"(?i)\bre-?learn|\bacross\s+(sessions|conversations|projects)|\bremember\s+(this|it|us|me)\b"
    r"|\bevery\s+(future|new|next)\s+(session|conversation|chat)\b|\bso\s+(that\s+)?you\s+(always|never\s+forget)")
SKILLS_DIR = re.compile(r"(?i)\.claude/skills|\bskills/")


def agent_config_severity(text: str, m: re.Match, user_invoked: bool = False) -> str:
    """medium for an unprompted write into the agent's own config, low when the user is in the loop."""
    if user_invoked:
        return "low"                                      # prompts run only when the user picks them
    before = text[max(0, m.start() - 300):m.end()]
    if any(label == "installs code into agent config" and rx.search(text) for label, _, rx in RULES):
        return "medium"                                   # downloading code never gets the consent discount
    if SELF_PERSIST.search(text[max(0, m.start() - 300):m.end() + 200]):
        return "medium"
    if CONSENT.search(before):
        return "low"
    if SKILLS_DIR.search(m.group(0)) and SKILL_INSTALLER.search(text[:m.end()]):
        return "low"                                      # a skill installer writing the skill it fetched
    return "medium"


def looks_encoded(s: str) -> bool:
    """Base64 payloads mix cases and digits with few slashes; hex strings, slash-separated
    word lists and long identifiers don't."""
    if re.fullmatch(r"[0-9a-fA-F]+", s) or s.count("/") > len(s) / 25:
        return False
    if not (re.search(r"[a-z]", s) and re.search(r"[A-Z]", s) and re.search(r"[0-9]", s)):
        return False
    # A hidden instruction has to decode to text the model can read. Base64 of binary data
    # (an OpenTimestamps proof shown as a tool's example input, seen 2026-10-13) is just data.
    body = s.rstrip("=")
    try:
        raw = base64.b64decode(body[: len(body) // 4 * 4], validate=True)
    except (binascii.Error, ValueError):
        return True
    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in raw)
    return printable >= 0.85 * len(raw)


# Invisible / direction-control characters have no business in text a model reads:
# zero-width, bidi overrides, Unicode tag characters (ASCII smuggling), and terminal
# escape sequences (ESC/BEL can rewrite what a terminal shows; ATR-2026-00259).
HIDDEN_CHARS = re.compile("[\x1b\x07​-‏‪-‮⁠-⁤⁦-⁩﻿\U000e0000-\U000e007f]")

JOINER_SCRIPTS = re.compile("[\u0600-\u06ff\u0750-\u077f\u0900-\u0dff\U0001f300-\U0001faff]")
LONG_DESCRIPTION = 2500


EXAMPLE_BEFORE = re.compile(r"(?i)\b(example|sample|e\.g\.|for instance|such as|like this)\b")


def _inside_quoted_example(text: str, start: int) -> bool:
    """A sample attack shown inside a quoted string after "example"/"sample" (an injection
    *detector* describing its input, seen 2026-10-11) is data being described, not an order."""
    before = text[max(0, start - 200):start]
    in_quotes = before.count('"') % 2 == 1 or before.count("“") > before.count("”")
    return in_quotes and bool(EXAMPLE_BEFORE.search(before))


def _counts(label: str, text: str, m: re.Match) -> bool:
    if label == "encoded payload":
        return looks_encoded(m.group(0))
    if label in MENTION_RULES or label in ("concealment from user", "outcome deception"):
        if _inside_quoted_example(text, m.start()):
            return False
    if label in MENTION_RULES:
        return not MENTION_BEFORE.search(text[max(0, m.start() - 80):m.start()])
    return True


def scan_text(text: str, user_invoked: bool = False) -> list[tuple[str, str, str]]:
    """Return [(label, severity, snippet)] for one piece of model-visible text.
    user_invoked: the text only reaches the model when the user chooses it (prompts)."""
    if not text:
        return []
    hits = []
    for label, sev, rx in RULES:
        m = next((m for m in rx.finditer(text) if _counts(label, text, m)), None)
        if m:
            if label == "writes into agent config":
                sev = agent_config_severity(text, m, user_invoked)
            a, b = max(0, m.start() - 30), min(len(text), m.end() + 30)
            hits.append((label, sev, text[a:b].replace("\n", " ")))
    hidden = HIDDEN_CHARS.findall(text)
    if hidden and JOINER_SCRIPTS.search(text):
        # ZWNJ/ZWJ are ordinary in Persian, Arabic, Indic scripts and emoji sequences
        hidden = [c for c in hidden if c not in "\u200c\u200d"]
    if hidden:
        codes = sorted({f"U+{ord(c):04X}" for c in hidden})
        hits.append(("hidden unicode characters", "critical", f"{len(hidden)} chars: {', '.join(codes[:6])}"))
    # Independent indicators in one text compound: a fake <IMPORTANT> tag on its own
    # might be sloppy docs, but a tag plus a credential path is an attack.
    serious = {label for label, sev, _ in hits if sev in ("critical", "high") or label == "sensitive file target"}
    if len(serious) >= 2 and not any(sev == "critical" for _, sev, _ in hits):
        hits.append(("multiple injection indicators", "critical", ", ".join(sorted(serious))))
    return hits


def schema_texts(schema: dict, path: str = "") -> list[tuple[str, str]]:
    """Every description/title/default/enum string nested in a JSON schema."""
    out = []
    if not isinstance(schema, dict):
        return out
    for key in ("description", "title"):
        if isinstance(schema.get(key), str):
            out.append((f"{path or 'schema'}.{key}", schema[key]))
    if isinstance(schema.get("default"), str):
        out.append((f"{path or 'schema'}.default", schema["default"]))
    for name, sub in (schema.get("properties") or {}).items():
        out.extend(schema_texts(sub, f"{path}.{name}" if path else name))
    for key in ("items", "additionalProperties"):
        if isinstance(schema.get(key), dict):
            out.extend(schema_texts(schema[key], f"{path}[]" if path else "[]"))
    for key in ("anyOf", "oneOf", "allOf"):
        for i, sub in enumerate(schema.get(key) or []):
            out.extend(schema_texts(sub, f"{path}<{key}{i}>"))
    return out


def tool_texts(tool: dict) -> list[tuple[str, str]]:
    """(location, text) for every model-visible string on a tool."""
    out = [("description", tool.get("description") or "")]
    if tool.get("title"):
        out.append(("title", tool["title"]))
    out.extend(schema_texts(tool.get("inputSchema") or {}))
    return out


def analyze_descriptions(tools: list[dict], llm_hook=None) -> list[Finding]:
    """Heuristic pass over every tool (INJ-HEUR), plus an optional second opinion
    (INJ-LLM). llm_hook: (name, description) -> ("clean"|"suspicious", reason)."""
    findings = []
    for t in tools or []:
        name = t.get("name")
        for where, text in tool_texts(t):
            for label, sev, snippet in scan_text(text):
                findings.append(Finding(
                    "INJ-HEUR", sev, f"Injection indicator in tool '{name}': {label}",
                    f"{where}: …{snippet}…",
                    "Text in tool metadata is read by the model as instructions. Do not install, "
                    "or pin and review the server source before trusting it.",
                    tool_name=name))
        desc = t.get("description") or ""
        if len(desc) > LONG_DESCRIPTION:
            findings.append(Finding(
                "INJ-HEUR", "info", f"Very long description on '{name}' ({len(desc)} chars)",
                "Long descriptions cost context on every turn and make hidden instructions easier to bury.",
                "Review the full text once.", tool_name=name))
        if llm_hook:
            try:
                verdict, reason = llm_hook(name, desc)
            except Exception as e:
                verdict, reason = "error", str(e)
            if verdict == "suspicious":
                findings.append(Finding("INJ-LLM", "medium", f"LLM flagged description of '{name}'",
                                        reason, "Review this description manually.", tool_name=name))
    return findings
