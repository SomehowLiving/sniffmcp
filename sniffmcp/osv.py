"""Known-malware and known-vulnerability lookups via OSV.dev (free, public, no key).

OSV aggregates the OpenSSF malicious-packages feed (IDs "MAL-…") and vulnerability
databases (GHSA, PYSEC, CVE aliases). We use:
  POST /v1/querybatch   up to 1000 (package, version) queries per call -> vuln IDs
  GET  /v1/vulns/{id}   summary, aliases, severity for each ID we need to show

Checks run *before* a stdio server is spawned: a scanner must not execute a package
that is already known to be malware in order to find out it is malicious.
Set SNIFFMCP_OFFLINE=1 to skip all lookups.
"""
from __future__ import annotations
import asyncio, os, re

import httpx2

from . import __version__
from .models import Finding

API = "https://api.osv.dev/v1"
ECOSYSTEM = {"npm": "npm", "pypi": "PyPI"}
BATCH = 1000
UA = {"User-Agent": f"sniffmcp/{__version__}"}
GHSA_SEVERITY = {"CRITICAL": "high", "HIGH": "high", "MODERATE": "medium", "MEDIUM": "medium", "LOW": "low"}


def offline() -> bool:
    return os.environ.get("SNIFFMCP_OFFLINE") == "1"


def split_spec(ecosystem: str, spec: str) -> tuple[str, str | None]:
    """'@scope/pkg@1.2.3' -> ('@scope/pkg', '1.2.3'); 'pkg==1.0' / 'pkg[extra]@1.0' -> ('pkg', '1.0')."""
    if ecosystem == "npm":
        at = spec.rfind("@")
        if at > 0:
            ver = spec[at + 1:]
            return spec[:at], (ver if re.match(r"^v?\d+\.\d+\.\d+", ver) else None)
        return spec, None
    m = re.match(r"^([A-Za-z0-9._-]+)(\[[^\]]*\])?\s*(?:==|@)\s*v?([\w.+-]+)$", spec)
    if m:
        return m.group(1), m.group(3)
    return re.sub(r"\[.*\]$", "", spec.strip()), None


async def latest_version(http, ecosystem: str, name: str) -> str | None:
    """What an unpinned `npx pkg` / `uvx pkg` would run today."""
    try:
        if ecosystem == "npm":
            r = await http.get(f"https://registry.npmjs.org/{name.replace('/', '%2F')}",
                               headers={"Accept": "application/vnd.npm.install-v1+json"})
            return (r.json().get("dist-tags") or {}).get("latest") if r.status_code == 200 else None
        r = await http.get(f"https://pypi.org/pypi/{name}/json")
        return (r.json().get("info") or {}).get("version") if r.status_code == 200 else None
    except Exception:
        return None


async def query_batch(http, queries: list[tuple[str, str, str | None]]) -> list[list[str]]:
    """[(ecosystem, name, version|None)] -> [[vuln ids]] in the same order."""
    out: list[list[str]] = []
    for i in range(0, len(queries), BATCH):
        chunk = queries[i:i + BATCH]
        body = {"queries": [{"package": {"name": n, "ecosystem": ECOSYSTEM[e]}, **({"version": v} if v else {})}
                            for e, n, v in chunk]}
        r = await http.post(f"{API}/querybatch", json=body)
        r.raise_for_status()
        out.extend([[v["id"] for v in (res.get("vulns") or [])] for res in r.json().get("results", [])])
    return out


async def details(http, ids, concurrency: int = 10) -> dict[str, dict]:
    sem, out = asyncio.Semaphore(concurrency), {}

    async def one(vid):
        async with sem:
            try:
                r = await http.get(f"{API}/vulns/{vid}")
                out[vid] = r.json() if r.status_code == 200 else {"id": vid}
            except Exception:
                out[vid] = {"id": vid}
    await asyncio.gather(*(one(v) for v in set(ids)))
    return out


def severity(vuln: dict) -> str:
    if vuln.get("id", "").startswith("MAL-"):
        return "critical"
    ghsa = str((vuln.get("database_specific") or {}).get("severity", "")).upper()
    return GHSA_SEVERITY.get(ghsa, "medium")


def describe(vuln: dict) -> str:
    aliases = [a for a in vuln.get("aliases") or [] if a.startswith("CVE-")]
    return " ".join(filter(None, [vuln.get("id"), f"({', '.join(aliases[:2])})" if aliases else "",
                                  "—", (vuln.get("summary") or "no summary")[:160]]))


async def advisories_for_spec(ecosystem: str, spec: str) -> list[Finding]:
    """Findings for one package spec as it would be launched (pinned, or today's latest)."""
    name, version = split_spec(ecosystem, spec)
    pinned = version is not None
    try:
        async with httpx2.AsyncClient(timeout=20, headers=UA) as http:
            version = version or await latest_version(http, ecosystem, name)
            at_version, any_version = await query_batch(http, [(ecosystem, name, version), (ecosystem, name, None)])
            info = await details(http, at_version + [i for i in any_version if i.startswith("MAL-")])
    except Exception as e:
        return [Finding("SM-12", "info", "OSV lookup failed; package not checked for advisories",
                        f"{type(e).__name__}: {e}"[:200], "Retry online, or check https://osv.dev manually.")]
    where = f"{name}@{version}" if version else name
    note = "" if pinned else " (unpinned: this is today's latest, which is what npx/uvx would run)"
    out = []
    for vid in at_version:
        v = info.get(vid, {"id": vid})
        if vid.startswith("MAL-"):
            out.append(Finding("SM-11", "critical", f"Known malicious package: {where}", describe(v) + note,
                               "Remove this server now. If it ever ran, rotate every credential it could reach.",
                               kind="malware"))
        else:
            out.append(Finding("SM-12", severity(v), f"Known vulnerability in {where}", describe(v) + note,
                               "Upgrade to a fixed version (see the advisory).", kind="vulnerability"))
    other_mal = [i for i in any_version if i.startswith("MAL-") and i not in at_version]
    if other_mal:
        out.append(Finding("SM-11", "high", f"Other versions of {name} are known malware",
                           ", ".join(describe(info.get(i, {"id": i})) for i in other_mal[:2]),
                           "The package or its account was compromised before. Pin a version you have verified.",
                           kind="malware"))
    return out


def blocks_launch(findings: list[Finding]) -> bool:
    return any(f.check_id == "SM-11" and f.severity == "critical" for f in findings)
