"""Score = 100 minus severity-weighted deductions.

At most two deductions per check family, so one noisy class can't zero a score.
Grades are capped by the worst finding: any critical -> F ("don't install"),
any high -> C at best. A server with a confirmed injection must never "pass".
Suppressed findings are reported but never scored.
"""
from __future__ import annotations
from .models import Finding

WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
PER_FAMILY_CAP = 2
GRADES = [(90, "A"), (75, "B"), (55, "C"), (35, "D"), (0, "F")]


def score_findings(findings: list[Finding]) -> tuple[int, str]:
    by_family: dict[str, list[int]] = {}
    for f in findings:
        if f.suppressed:
            continue
        by_family.setdefault(f.check_id, []).append(WEIGHTS.get(f.severity, 0))
    deduction = sum(sum(sorted(ws, reverse=True)[:PER_FAMILY_CAP]) for ws in by_family.values())
    score = max(0, 100 - deduction)
    worst = max((w for ws in by_family.values() for w in ws), default=0)
    if worst >= WEIGHTS["critical"]:
        score = min(score, 34)
    elif worst >= WEIGHTS["high"]:
        score = min(score, 74)
    return score, next(g for floor, g in GRADES if score >= floor)


def summarize(findings: list[Finding]) -> dict[str, int]:
    out = {s: 0 for s in WEIGHTS}
    for f in findings:
        if not f.suppressed:
            out[f.severity] = out.get(f.severity, 0) + 1
    return out
