"""OAuth for scanning servers that require login (about a third of the registry).

The SDK's OAuthClientProvider does the protocol: discovery, dynamic client registration,
PKCE, token exchange and refresh, resource validation. This module supplies:

  - FileTokenStorage: one JSON file per server URL under ~/.sniffmcp/oauth/, owner-only
    (0600 file, 0700 directory). Tokens are never printed.
  - A loopback callback: a one-shot HTTP listener on 127.0.0.1 that receives the browser
    redirect. Its port is stored with the client registration, because the authorization
    server registered that exact redirect URI.
  - auth_for(): interactive (browser login, `sniffmcp login`) or stored-only (scan, fleet,
    watch). Stored-only never opens a browser; the crawler and CI never use OAuth at all.
"""
from __future__ import annotations
import asyncio, hashlib, json, os, re, socket, sys, time, webbrowser
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.shared.auth import AuthorizationCodeResult, OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

from . import __version__

LOGIN_TIMEOUT = 300   # seconds to finish the browser login
CALLBACK_PATH = "/callback"


def oauth_dir() -> Path:
    d = Path(os.environ.get("SNIFFMCP_HOME") or Path.home() / ".sniffmcp") / "oauth"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def _key(server_url: str) -> str:
    return hashlib.sha256(server_url.rstrip("/").encode()).hexdigest()[:24]


class FileTokenStorage(TokenStorage):
    """Tokens + client registration for one server URL, in one owner-only JSON file."""

    def __init__(self, server_url: str):
        self.server_url = server_url
        self.path = oauth_dir() / f"{_key(server_url)}.json"

    def _read(self) -> dict:
        try:
            return json.loads(self.path.read_text())
        except (OSError, ValueError):
            return {}

    def _write(self, data: dict) -> None:
        data["server_url"] = self.server_url
        data["updated_at"] = time.time()
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        os.replace(tmp, self.path)

    async def get_tokens(self) -> OAuthToken | None:
        t = self._read().get("tokens")
        return OAuthToken.model_validate(t) if t else None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        data = self._read()
        data["tokens"] = tokens.model_dump(mode="json", exclude_none=True)
        self._write(data)

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        c = self._read().get("client_info")
        return OAuthClientInformationFull.model_validate(c) if c else None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        data = self._read()
        data["client_info"] = client_info.model_dump(mode="json", exclude_none=True)
        self._write(data)

    # --- sniffmcp-specific ---
    def has_tokens(self) -> bool:
        return bool(self._read().get("tokens"))

    def callback_port(self) -> int | None:
        return self._read().get("callback_port")

    def set_callback_port(self, port: int) -> None:
        data = self._read()
        data["callback_port"] = port
        self._write(data)

    def delete(self) -> bool:
        try:
            self.path.unlink()
            return True
        except FileNotFoundError:
            return False


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


_DONE_PAGE = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n"
              b"<!doctype html><title>SniffMCP</title><body style='font-family:sans-serif;padding:3em'>"
              b"<h2>&#x1F575;&#xFE0F; SniffMCP: login complete</h2><p>You can close this tab.</p></body>")


class LoopbackCallback:
    """One-shot listener for the OAuth redirect on 127.0.0.1:<port>/callback."""

    def __init__(self, port: int):
        self.port = port
        self.redirect_uri = f"http://127.0.0.1:{port}{CALLBACK_PATH}"
        self._result: asyncio.Future | None = None
        self._server: asyncio.base_events.Server | None = None

    async def start(self) -> None:
        self._result = asyncio.get_running_loop().create_future()
        try:
            self._server = await asyncio.start_server(self._handle, "127.0.0.1", self.port)
        except OSError as e:
            raise RuntimeError(f"port {self.port} is busy; free it, or run `sniffmcp logout` and log in again "
                               f"to register a new callback port ({e})") from None

    async def _handle(self, reader, writer):
        try:
            line = (await asyncio.wait_for(reader.readline(), 10)).decode("latin-1")
            target = line.split(" ")[1] if line.count(" ") >= 2 else ""
            url = urlparse(target)
            if url.path != CALLBACK_PATH or self._result.done():
                writer.write(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n")
                return
            q = {k: v[0] for k, v in parse_qs(url.query).items()}
            if "error" in q:
                self._result.set_exception(RuntimeError(
                    f"authorization refused: {q.get('error')} {q.get('error_description', '')}".strip()))
            elif "code" in q:
                self._result.set_result(AuthorizationCodeResult(code=q["code"], state=q.get("state"),
                                                                iss=q.get("iss")))
            else:
                writer.write(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                return
            writer.write(_DONE_PAGE)
        except Exception:
            pass
        finally:
            try:
                await writer.drain()
                writer.close()
            except Exception:
                pass

    async def wait(self) -> AuthorizationCodeResult:
        try:
            return await asyncio.wait_for(self._result, LOGIN_TIMEOUT)
        except asyncio.TimeoutError:
            raise RuntimeError(f"login not completed within {LOGIN_TIMEOUT // 60} minutes") from None
        finally:
            await self.close()

    async def close(self) -> None:
        if self._server:
            self._server.close()
            self._server = None


async def _open_browser(url: str) -> None:
    print(f"\n  Opening your browser to log in. If it doesn't open, visit:\n\n  {url}\n", file=sys.stderr)
    try:
        webbrowser.open(url)
    except Exception:
        pass


WRITE_SCOPE = re.compile(r"(?i)(write|admin|delete|manage|modify|create|update|edit|full|owner|sudo|\*)")


def read_only_scopes(scope: str | None) -> str | None:
    """A scanner only *lists* tools, so ask for read scopes only. The SDK otherwise requests
    every scope a server advertises (devfolio: profile.write, projects.write, ...). Keeps
    offline_access so stored logins can refresh. If nothing read-like is left, omit the
    scope and let the server apply its default."""
    override = os.environ.get("SNIFFMCP_OAUTH_SCOPE")
    if override:   # escape hatch for servers that mishandle partial scopes: "all", or an exact list
        return scope if override == "all" else override
    if not scope:
        return scope
    kept = [s for s in scope.split() if not WRITE_SCOPE.search(s)]
    return " ".join(kept) if [s for s in kept if s != "offline_access"] else None


class ReadOnlyClientMetadata(OAuthClientMetadata):
    """Client metadata whose scope can only ever hold read scopes, however the SDK sets it
    (initial selection, WWW-Authenticate challenge, or step-up)."""

    def __init__(self, **data):
        data["scope"] = read_only_scopes(data.get("scope"))
        super().__init__(**data)

    def __setattr__(self, name, value):
        if name == "scope":
            value = read_only_scopes(value)
        super().__setattr__(name, value)


def auth_for(server_url: str, interactive: bool = False, open_url=None) -> OAuthClientProvider | None:
    """OAuth provider for server_url.
    interactive=False: only if tokens are already stored (refresh works; no browser ever).
    interactive=True: may run the browser login."""
    storage = FileTokenStorage(server_url)
    if not interactive and not storage.has_tokens():
        return None
    port = storage.callback_port()
    if port is None:
        port = _free_port()
        storage.set_callback_port(port)
    callback = LoopbackCallback(port)

    async def redirect_handler(url: str) -> None:
        if not interactive:
            raise RuntimeError("stored login has expired")
        await callback.start()
        await (open_url or _open_browser)(url)   # looked up at call time (tests replace it)

    async def callback_handler() -> AuthorizationCodeResult:
        return await callback.wait()

    metadata = ReadOnlyClientMetadata(
        client_name="SniffMCP", client_uri="https://pypi.org/project/sniffmcp-cli/",
        software_id="sniffmcp", software_version=__version__,
        redirect_uris=[callback.redirect_uri], token_endpoint_auth_method="none")
    return OAuthClientProvider(server_url=server_url, client_metadata=metadata, storage=storage,
                               redirect_handler=redirect_handler, callback_handler=callback_handler)


def logged_in_servers() -> list[dict]:
    out = []
    for p in sorted(oauth_dir().glob("*.json")):
        try:
            d = json.loads(p.read_text())
        except ValueError:
            continue
        if d.get("tokens"):
            out.append({"server_url": d.get("server_url"), "updated_at": d.get("updated_at")})
    return out
