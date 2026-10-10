"""OAuth end to end against a real OAuth-protected MCP server (tests/fixtures/oauth_server.py):
discovery, dynamic client registration, PKCE, loopback callback, token storage, reuse, logout."""
import os, socket, stat, subprocess, sys, time
from pathlib import Path

import httpx2
import pytest

from sniffmcp import oauth
from sniffmcp.client import ConnectError, fetch_manifest

FIXTURE = Path(__file__).parent / "fixtures" / "oauth_server.py"


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def server(tmp_path, monkeypatch):
    monkeypatch.setenv("SNIFFMCP_HOME", str(tmp_path / "home"))
    port = _free_port()
    proc = subprocess.Popen([sys.executable, str(FIXTURE), str(port)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for _ in range(100):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.1)
    yield f"http://127.0.0.1:{port}/mcp"
    proc.terminate()
    proc.wait(5)


@pytest.fixture
def fake_browser(monkeypatch):
    """Stands in for the user's browser: follows the authorization URL, whose (auto-approving)
    server redirects to our loopback callback with the code."""
    visited = []

    async def browser(url):
        visited.append(url)
        async with httpx2.AsyncClient(follow_redirects=True, timeout=10) as http:
            await http.get(url)
    monkeypatch.setattr(oauth, "_open_browser", browser)
    return visited


async def test_unauthenticated_scan_points_to_login(server):
    with pytest.raises(ConnectError) as e:
        await fetch_manifest({"url": server, "timeout": 15})
    assert "sniffmcp login" in str(e.value)


async def test_login_then_reuse_without_browser(server, fake_browser):
    manifest = await fetch_manifest({"url": server, "timeout": 15}, auth="interactive")
    assert [t["name"] for t in manifest["tools"]] == ["private_notes"]
    assert len(fake_browser) == 1 and "code_challenge=" in fake_browser[0]   # PKCE

    # stored login: no browser this time
    manifest = await fetch_manifest({"url": server, "timeout": 15})
    assert manifest["tools"] and len(fake_browser) == 1

    # token file is owner-only and lives under SNIFFMCP_HOME
    files = list(oauth.oauth_dir().glob("*.json"))
    assert len(files) == 1
    assert stat.S_IMODE(files[0].stat().st_mode) == 0o600
    assert stat.S_IMODE(oauth.oauth_dir().stat().st_mode) == 0o700
    assert [r["server_url"] for r in oauth.logged_in_servers()] == [server]


async def test_crawler_mode_never_uses_stored_logins(server, fake_browser):
    await fetch_manifest({"url": server, "timeout": 15}, auth="interactive")
    with pytest.raises(ConnectError):
        await fetch_manifest({"url": server, "timeout": 15}, auth="none")


async def test_explicit_authorization_header_wins(server, fake_browser):
    await fetch_manifest({"url": server, "timeout": 15}, auth="interactive")
    with pytest.raises(ConnectError):   # a wrong explicit header is used as-is, not replaced by OAuth
        await fetch_manifest({"url": server, "headers": {"Authorization": "Bearer nope"}, "timeout": 15})


async def test_logout_forgets_the_login(server, fake_browser):
    await fetch_manifest({"url": server, "timeout": 15}, auth="interactive")
    assert oauth.FileTokenStorage(server).delete()
    with pytest.raises(ConnectError):
        await fetch_manifest({"url": server, "timeout": 15})


async def test_callback_rejects_wrong_path_and_reports_denial():
    cb = oauth.LoopbackCallback(_free_port())
    await cb.start()
    async with httpx2.AsyncClient() as http:
        assert (await http.get(f"http://127.0.0.1:{cb.port}/other?code=x")).status_code == 404
        await http.get(f"{cb.redirect_uri}?error=access_denied&error_description=user+said+no")
    with pytest.raises(RuntimeError, match="access_denied"):
        await cb.wait()


def test_only_read_scopes_are_requested():
    devfolio = ("profile.read profile.write hackathons.read applications.read applications.write "
                "teams.read projects.read projects.write offline_access")   # real, 2026-10-10
    assert oauth.read_only_scopes(devfolio) == (
        "profile.read hackathons.read applications.read teams.read projects.read offline_access")
    assert oauth.read_only_scopes("repo:write admin:org") is None          # nothing read-like: omit scope
    assert oauth.read_only_scopes("offline_access") is None
    assert oauth.read_only_scopes(None) is None
    md = oauth.ReadOnlyClientMetadata(redirect_uris=["http://127.0.0.1:1/callback"], scope="a.read a.write")
    assert md.scope == "a.read"
    md.scope = "b.read b.admin offline_access"           # how the SDK sets it after discovery
    assert md.scope == "b.read offline_access"


async def test_oauth_scan_has_no_missing_credentials_note(server, fake_browser):
    from sniffmcp.engine import scan
    report, _ = await scan({"url": server, "timeout": 15}, auth="interactive")
    assert not any("no client credentials" in f.title for f in report.findings)


def test_scope_override(monkeypatch):
    monkeypatch.setenv("SNIFFMCP_OAUTH_SCOPE", "all")
    assert oauth.read_only_scopes("a.read a.write") == "a.read a.write"
    monkeypatch.setenv("SNIFFMCP_OAUTH_SCOPE", "x.read")
    assert oauth.read_only_scopes("a.read a.write") == "x.read"
