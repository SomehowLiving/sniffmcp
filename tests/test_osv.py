"""OSV integration, offline (network calls replaced)."""
import pytest

from sniffmcp import osv
from sniffmcp.engine import scan


def test_split_spec():
    assert osv.split_spec("npm", "@scope/pkg@1.2.3") == ("@scope/pkg", "1.2.3")
    assert osv.split_spec("npm", "@scope/pkg") == ("@scope/pkg", None)
    assert osv.split_spec("npm", "pkg@latest") == ("pkg", None)
    assert osv.split_spec("npm", "pkg@99.0.2025091-3.10") == ("pkg", "99.0.2025091-3.10")
    assert osv.split_spec("pypi", "mcp-server-fetch==2025.4.7") == ("mcp-server-fetch", "2025.4.7")
    assert osv.split_spec("pypi", "pkg[cli]@1.0") == ("pkg", "1.0")
    assert osv.split_spec("pypi", "mcp-server-git") == ("mcp-server-git", None)


def test_severity_mapping():
    assert osv.severity({"id": "MAL-2025-1"}) == "critical"
    assert osv.severity({"id": "GHSA-x", "database_specific": {"severity": "MODERATE"}}) == "medium"
    assert osv.severity({"id": "GHSA-x", "database_specific": {"severity": "CRITICAL"}}) == "high"


@pytest.fixture
def fake_osv(monkeypatch):
    db = {}

    async def latest(http, eco, name):
        return "9.9.9"

    async def batch(http, queries):
        return [db.get((n, v), []) for _, n, v in queries]

    async def det(http, ids, concurrency=10):
        return {i: {"id": i, "summary": f"summary of {i}", "aliases": ["CVE-2026-0001"],
                    "database_specific": {"severity": "HIGH"}} for i in ids}

    monkeypatch.setattr(osv, "latest_version", latest)
    monkeypatch.setattr(osv, "query_batch", batch)
    monkeypatch.setattr(osv, "details", det)
    monkeypatch.delenv("SNIFFMCP_OFFLINE", raising=False)
    return db


async def test_known_malware_is_reported_and_never_launched(fake_osv):
    fake_osv[("evil-mcp", "1.0.0")] = ["MAL-2026-1"]
    fake_osv[("evil-mcp", None)] = ["MAL-2026-1"]
    # if this were spawned it would fail: the package doesn't exist
    report, manifest = await scan({"command": "npx", "args": ["-y", "evil-mcp@1.0.0"]})
    assert manifest["tools"] == [] and "not launched" in manifest["errors"][0]
    assert report.grade == "F"
    assert any(f.check_id == "SM-11" and f.severity == "critical" for f in report.findings)


async def test_unpinned_checks_todays_latest(fake_osv):
    fake_osv[("some-mcp", "9.9.9")] = ["GHSA-abcd"]
    findings = await osv.advisories_for_spec("npm", "some-mcp")
    (f,) = findings
    assert f.check_id == "SM-12" and f.severity == "high"
    assert "some-mcp@9.9.9" in f.title and "unpinned" in f.evidence and "CVE-2026-0001" in f.evidence


async def test_malware_in_other_versions_is_high(fake_osv):
    fake_osv[("was-hijacked", None)] = ["MAL-2025-7"]
    findings = await osv.advisories_for_spec("npm", "was-hijacked@2.0.0")
    assert [(f.check_id, f.severity) for f in findings] == [("SM-11", "high")]


async def test_offline_skips_lookup(monkeypatch):
    monkeypatch.setenv("SNIFFMCP_OFFLINE", "1")
    assert osv.offline()
