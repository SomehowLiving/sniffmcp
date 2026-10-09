"""Connect to a target MCP server and pull the manifest the agent would see.

Uses the official SDK (mcp>=2). `Client(mode="auto")` probes the 2026-07-28
`server/discover` and falls back to the legacy initialize handshake, so both
protocol generations scan the same way.

Config shapes accepted (same as Claude / Cursor / Claude Code configs):
  {"command": "npx", "args": ["-y", "pkg@1.2.3"], "env": {...}, "cwd": "..."}
  {"url": "https://host/mcp", "headers": {...}}                 # Streamable HTTP
  {"type": "sse", "url": "https://host/sse", "headers": {...}}  # legacy SSE
Optional: "timeout" (seconds).
"""
from __future__ import annotations
import os, re, tempfile

import anyio
from mcp import Client
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamable_http_client
from mcp.client.sse import sse_client
from mcp.shared._httpx_utils import create_mcp_http_client
from mcp.types import Implementation

from . import __version__

DEFAULT_TIMEOUT_STDIO = 90.0   # first `npx -y` / `uvx` run downloads the package
DEFAULT_TIMEOUT_HTTP = 30.0
MAX_PAGES = 50


class ConnectError(Exception):
    """Target could not be reached, spawned, or did not complete the handshake."""


_VAR = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


def _expand(value: str) -> str:
    """Expand ${VAR} and ${VAR:-default} the way Claude Code / Cursor configs do."""
    return _VAR.sub(lambda m: os.environ.get(m.group(1), m.group(2) or ""), value)


def transport_of(config: dict) -> str:
    if "url" not in config:
        return "stdio"
    if config.get("type") == "sse" or config.get("transport") == "sse":
        return "sse"
    return "streamable_http"


def _innermost(e: BaseException) -> BaseException:
    while isinstance(e, BaseExceptionGroup) and e.exceptions:
        e = e.exceptions[0]
    return e


async def _list_all(fetch, attr: str) -> list[dict]:
    out, cursor = [], None
    for _ in range(MAX_PAGES):
        page = await fetch(cursor=cursor)
        out.extend(x.model_dump(mode="json", by_alias=True, exclude_none=True)
                   for x in getattr(page, attr))
        cursor = page.next_cursor
        if not cursor:
            break
    return out


async def _collect(client: Client) -> dict:
    caps = client.server_capabilities
    manifest = {"tools": [], "resources": [], "prompts": [],
                "server_info": {}, "instructions": client.instructions or "",
                "protocol_version": client.protocol_version, "errors": []}
    if client.server_info:
        manifest["server_info"] = client.server_info.model_dump(mode="json", exclude_none=True)
    # Only ask for what the server advertises; some servers error on unknown methods.
    for attr, cap, fetch in (("tools", caps.tools, client.list_tools),
                             ("resources", caps.resources, client.list_resources),
                             ("prompts", caps.prompts, client.list_prompts)):
        if cap is None:
            continue
        try:
            manifest[attr] = await _list_all(fetch, attr)
        except Exception as e:  # a failed list is reported, not fatal
            manifest["errors"].append(f"{attr}/list failed: {_innermost(e)}")
    return manifest


def _transport_for(config: dict, errlog):
    kind = transport_of(config)
    if kind == "stdio":
        cmd = config.get("command")
        if not cmd or not isinstance(cmd, str):
            raise ConnectError("config has neither 'command' nor 'url'")
        env = {k: _expand(str(v)) for k, v in (config.get("env") or {}).items()}
        params = StdioServerParameters(command=_expand(cmd),
                                       args=[_expand(str(a)) for a in config.get("args") or []],
                                       env=env or None, cwd=config.get("cwd"))
        return stdio_client(params, errlog=errlog)
    url = _expand(config["url"])
    headers = {k: _expand(str(v)) for k, v in (config.get("headers") or {}).items()}
    if kind == "sse":
        return sse_client(url, headers=headers or None)
    return streamable_http_client(url, http_client=create_mcp_http_client(headers=headers or None))


async def fetch_manifest(config: dict, client_name: str = "sniffmcp") -> dict:
    """Connect, negotiate, and return tools/resources/prompts/server_info/instructions."""
    kind = transport_of(config)
    timeout = float(config.get("timeout") or
                    (DEFAULT_TIMEOUT_STDIO if kind == "stdio" else DEFAULT_TIMEOUT_HTTP))
    with tempfile.TemporaryFile(mode="w+", encoding="utf-8", errors="replace") as errlog:
        try:
            transport = _transport_for(config, errlog)
            with anyio.fail_after(timeout):
                async with Client(transport, mode="auto", cache=None,
                                  client_info=Implementation(name=client_name, version=__version__)) as client:
                    return await _collect(client)
        except ConnectError:
            raise
        except TimeoutError:
            raise ConnectError(f"timed out after {timeout:.0f}s{_stderr_tail(errlog)}") from None
        except Exception as e:
            inner = _innermost(e)
            if kind != "stdio":
                hint = await _http_status_hint(config)
                if hint:
                    raise ConnectError(hint) from None
            raise ConnectError(f"{type(inner).__name__}: {inner}{_stderr_tail(errlog)}") from None


async def _http_status_hint(config: dict) -> str | None:
    """After a failed remote connect, say *why* in terms a user can act on."""
    import httpx2
    headers = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream",
               **{k: _expand(str(v)) for k, v in (config.get("headers") or {}).items()}}
    body = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "sniffmcp", "version": "0"}}}
    try:
        async with httpx2.AsyncClient(timeout=10) as http:
            r = await http.post(_expand(config["url"]), json=body, headers=headers)
    except Exception:
        return None
    if r.status_code in (401, 403):
        oauth = "resource_metadata" in r.headers.get("www-authenticate", "")
        return (f"requires authentication (HTTP {r.status_code}"
                f"{', OAuth' if oauth else ''}); pass credentials in \"headers\" to scan it")
    if r.status_code >= 400:
        return f"HTTP {r.status_code} from server"
    return None


def _stderr_tail(errlog) -> str:
    try:
        errlog.seek(0)
        lines = [l.strip() for l in errlog.read().splitlines() if l.strip()]
    except Exception:
        return ""
    return (" | stderr: " + " / ".join(lines[-3:])[:300]) if lines else ""
