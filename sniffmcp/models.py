"""Core data types shared by checks, scoring, reports and the watcher."""
from __future__ import annotations
import hashlib, json, time
from dataclasses import dataclass, field, asdict


@dataclass
class Finding:
    check_id: str
    severity: str                 # critical | high | medium | low | info
    title: str
    evidence: str = ""
    remediation: str = ""
    tool_name: str | None = None
    kind: str = ""                # for drift findings: breaking | risky | benign
    suppressed: bool = False


@dataclass
class ScanReport:
    target: str
    transport: str
    score: int
    grade: str
    findings: list[Finding]
    manifest_hash: str
    tool_count: int
    scanned_at: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        return d


def _tool_key(t: dict) -> dict:
    return {"name": t.get("name"), "description": t.get("description") or "",
            "inputSchema": t.get("inputSchema") or {}, "annotations": t.get("annotations") or {}}


def canonical_manifest_hash(tools, resources=None, prompts=None) -> str:
    """SHA-256 over everything the agent sees: tool names, descriptions, input
    schemas (parameter descriptions are an injection surface too), annotations,
    resources and prompts. Order-independent."""
    blob = {
        "tools": sorted((_tool_key(t) for t in tools or []), key=lambda t: t["name"] or ""),
        "resources": sorted(({"uri": str(r.get("uri", "")), "name": r.get("name"),
                              "description": r.get("description") or ""}
                             for r in resources or []), key=lambda r: r["uri"]),
        "prompts": sorted(({"name": p.get("name"), "description": p.get("description") or ""}
                           for p in prompts or []), key=lambda p: p["name"] or ""),
    }
    return hashlib.sha256(json.dumps(blob, sort_keys=True).encode()).hexdigest()
