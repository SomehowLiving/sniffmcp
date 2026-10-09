"""Stable report contracts, Sentinel-style.

- Rule IDs are compatibility contracts: never renumber or reuse.
- SARIF 2.1.0 for GitHub code scanning.
- Baseline diff: findings matched against a previous report stay visible
  but don't fail CI.
- Suppressions: reason-bearing directives, always visible in reports.
"""
from __future__ import annotations
import json, re
from pathlib import Path
from .models import Finding

RULES_META = {
    "MA-01": ("Tool poisoning", "Hidden directives in server-level instructions.", "High"),
    "MA-02": ("Hardcoded credential", "Secrets found in the server configuration (args/env/config).", "Critical"),
    "MA-03": ("Rug pull / behavior drift", "Tools or descriptions changed after install-time baseline.", "Critical"),
    "MA-04": ("Excessive privileges", "Command execution or destructive tools; annotations that misstate a tool as read-only.", "High"),
    "MA-05": ("Sensitive data scope", "Tool or resource can reach env, credentials, or sensitive paths.", "High"),
    "MA-06": ("Insecure transport", "Plain HTTP or unauthenticated remote MCP endpoint.", "High"),
    "MA-07": ("Unpinned dependency", "Server launched via unpinned package runner (npx/uvx/pipx without version).", "Medium"),
    "MA-08": ("Oversized attack surface", "Unusually many tools, or duplicate tool names.", "Medium"),
    "MA-09": ("Prompt exposure", "Prompt descriptions contain directive-like content.", "High"),
    "MA-10": ("Config hygiene", "Launch command pipes a download into a shell, or TLS verification is disabled.", "High"),
    "MA-11": ("Known malicious package", "OSV / OpenSSF malicious-packages advisory (MAL-) for the launched package.", "Critical"),
    "MA-12": ("Known vulnerability", "OSV advisory (GHSA / PYSEC / CVE) for the launched package version.", "High"),
    "INJ-HEUR": ("Injection indicator", "Injection pattern in a tool description, title, or parameter description.", "High"),
    "INJ-LLM":  ("LLM-flagged description", "LLM second-opinion flagged a tool description.", "Medium"),
}

# mcp-audit IDs are our own and do NOT follow OWASP numbering (OWASP MCP01 is token
# mismanagement; our MA-01 is poisoned server instructions). This map is the bridge.
# Source: OWASP MCP Top 10 (beta, 2025), https://owasp.org/www-project-mcp-top-10/
OWASP_MCP = {
    "MCP01": "Token Mismanagement & Secret Exposure",
    "MCP02": "Privilege Escalation via Scope Creep",
    "MCP03": "Tool Poisoning",
    "MCP04": "Software Supply Chain Attacks & Dependency Tampering",
    "MCP05": "Command Injection & Execution",
    "MCP06": "Intent Flow Subversion",
    "MCP07": "Insufficient Authentication & Authorization",
    "MCP08": "Lack of Audit and Telemetry",
    "MCP09": "Shadow MCP Servers",
    "MCP10": "Context Injection & Over-Sharing",
}
OWASP_FOR_CHECK = {
    "INJ-HEUR": ["MCP03", "MCP06"], "INJ-LLM": ["MCP03"],
    "MA-01": ["MCP03", "MCP06"], "MA-02": ["MCP01"], "MA-03": ["MCP03", "MCP04"],
    "MA-04": ["MCP02", "MCP05"], "MA-05": ["MCP10", "MCP01"], "MA-06": ["MCP07"],
    "MA-07": ["MCP04"], "MA-08": ["MCP03"], "MA-09": ["MCP03"], "MA-10": ["MCP04", "MCP07"],
    "MA-11": ["MCP04"], "MA-12": ["MCP04"], "FLEET-01": ["MCP03"],
}

REPORT_SCHEMA = "mcp-audit/report@2.0.0"   # 2.0: check IDs renamed MCP-xx -> MA-xx

def to_sarif(findings: list[Finding], target: str = "mcp-target") -> dict:
    rules, results = [], []
    seen = set()
    for f in findings:
        fam = f.check_id
        if fam not in seen:
            seen.add(fam)
            name, desc, _ = RULES_META.get(fam, (fam, fam, "Medium"))
            rules.append({"id": fam, "name": name,
                          "shortDescription": {"text": f"{name} ({fam})"},
                          "fullDescription": {"text": desc},
                          "helpUri": f"https://mcp-audit.dev/rules/{fam}"})
        results.append({
            "ruleId": fam,
            "level": {"critical": "error", "high": "error", "medium": "warning",
                      "low": "note", "info": "note"}.get(f.severity, "warning"),
            "message": {"text": f"{f.title}. {f.evidence} Fix: {f.remediation}"},
            "locations": [{"logicalLocations": [{"name": f.tool_name or target,
                                                 "kind": "function" if f.tool_name else "module"}]}],
            "properties": {"severity": f.severity, "check_id": f.check_id,
                           "owasp_mcp": OWASP_FOR_CHECK.get(f.check_id, []),
                           "tags": [f"OWASP-{o}" for o in OWASP_FOR_CHECK.get(f.check_id, [])],
                           "suppressed": getattr(f, "suppressed", False)},
        })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "mcp-audit",
                                          "version": REPORT_SCHEMA,
                                          "rules": rules}},
                      "results": results}]}

# ---------- baseline diff ----------
def finding_key(f: Finding) -> str:
    return f"{f.check_id}|{f.tool_name or ''}|{f.title}"

def diff_baseline(findings: list[Finding], baseline: dict) -> list[Finding]:
    """Mark findings matched in the baseline as suppressed-for-gating but visible."""
    old = {finding_key_from_dict(x) for x in baseline.get("findings", [])}
    for f in findings:
        f.suppressed = finding_key(f) in old
    return findings

def finding_key_from_dict(d: dict) -> str:
    return f"{d.get('check_id','')}|{d.get('tool_name') or ''}|{d.get('title','')}"

# ---------- suppressions ----------
SUPPRESSION_RX = re.compile(r"mcp-audit:\s*ignore\[([A-Z0-9,\-\s]+)\]\s*reason=(.+)")
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

def apply_suppressions(findings: list[Finding], config_text: str = "", suppress_file: str | None = None) -> list[Finding]:
    """Parse reason-bearing directives from any text (config file, README) plus an
    optional suppressions JSON: {"MA-02": "reason", "MA-05:env_dump": "reason"}."""
    allowed = set()
    for m in SUPPRESSION_RX.finditer(config_text or ""):
        for rid in m.group(1).split(","):
            allowed.add(rid.strip())
    file_rules: dict[str, str] = {}
    if suppress_file:
        try:
            file_rules = json.loads(Path(suppress_file).read_text())
        except Exception:
            pass
    for f in findings:
        key = f"{f.check_id}:{f.tool_name}" if f.tool_name else f.check_id
        if f.check_id in allowed or key in file_rules or f.check_id in file_rules:
            f.suppressed = True
    return findings

def gate(findings: list[Finding], fail_on: str = "high") -> int:
    """Sentinel-style exit contract. 0 = pass, 1 = findings at/above threshold."""
    threshold = SEVERITY_RANK[fail_on]
    active = [f for f in findings if not getattr(f, "suppressed", False)]
    return 1 if any(SEVERITY_RANK.get(f.severity, 0) >= threshold for f in active) else 0

def to_json_report(target, score, grade, findings, manifest_hash) -> dict:
    return {"schema": REPORT_SCHEMA, "target": target, "score": score, "grade": grade,
            "manifest_hash": manifest_hash,
            "findings": [{"check_id": f.check_id, "severity": f.severity, "title": f.title,
                          "evidence": f.evidence, "remediation": f.remediation,
                          "tool_name": f.tool_name, "kind": f.kind,
                          "owasp_mcp": OWASP_FOR_CHECK.get(f.check_id, []),
                          "suppressed": getattr(f, "suppressed", False)}
                         for f in findings]}

# ---------- fleet SARIF (CI: annotate the config file itself) ----------
def _server_line(path: str, name: str) -> int:
    """1-based line where a server is defined in its config file, so code scanning can
    annotate the exact entry a pull request added."""
    key = f'"{name.rsplit(" (", 1)[0]}"'   # "name (project)" -> "name"
    try:
        for i, line in enumerate(Path(path).read_text().splitlines(), 1):
            if key in line:
                return i
    except OSError:
        pass
    return 1


def _artifact_uri(path: str) -> str:
    """Repo-relative when the file is under the working directory (GitHub requires that)."""
    import os
    rel = os.path.relpath(path)
    return (rel if not rel.startswith("..") else path).replace(os.sep, "/")


def fleet_to_sarif(fleet: dict, min_severity: str = "low") -> dict:
    floor = SEVERITY_RANK[min_severity]
    rules, seen, results, notes = [], set(), [], []
    for r in fleet["servers"]:
        if r["status"] != "ok":
            notes.append({"level": "warning", "message": {"text": f"{r['name']}: not analysed ({r['error'][:200]})"}})
            continue
        uri, line = _artifact_uri(r.get("source") or "mcp.json"), _server_line(r.get("source") or "", r["name"])
        for f in r["findings"]:
            if SEVERITY_RANK.get(f["severity"], 0) < floor:
                continue
            cid = f["check_id"]
            if cid not in seen:
                seen.add(cid)
                name, desc, _ = RULES_META.get(cid, (cid, cid, "Medium"))
                rules.append({"id": cid, "name": name, "shortDescription": {"text": f"{name} ({cid})"},
                              "fullDescription": {"text": desc},
                              "helpUri": f"https://github.com/SomehowLiving/mcp-audit#checks",
                              "properties": {"tags": ["security"] + [f"OWASP-{o}" for o in OWASP_FOR_CHECK.get(cid, [])]}})
            results.append({
                "ruleId": cid,
                "level": {"critical": "error", "high": "error", "medium": "warning"}.get(f["severity"], "note"),
                "message": {"text": f"MCP server '{r['name']}': {f['title']}. {f['evidence']} Fix: {f['remediation']}".strip()},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}},
                               "logicalLocations": [{"name": r["name"], "kind": "module"}]}],
                "properties": {"severity": f["severity"], "check_id": cid, "server": r["name"],
                               "owasp_mcp": OWASP_FOR_CHECK.get(cid, []), "suppressed": f.get("suppressed", False)},
            })
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "mcp-audit", "version": REPORT_SCHEMA,
                                          "informationUri": "https://github.com/SomehowLiving/mcp-audit",
                                          "rules": rules}},
                      "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": notes}],
                      "results": results}]}
