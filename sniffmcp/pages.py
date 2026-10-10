"""The small local pages a browser shows after an OAuth login (served from 127.0.0.1).

Self-contained: inline CSS, mascot images as data: URIs, no scripts, no external requests.
Anything that came from the URL is HTML-escaped; the CSP forbids scripts, and
Referrer-Policy keeps the authorization code in the URL from leaking anywhere.
"""
from __future__ import annotations
import base64, html
from functools import lru_cache
from importlib.resources import files
from urllib.parse import urlparse

CSP = "default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'"


@lru_cache(maxsize=None)
def _mascot(name: str) -> str:
    data = files("sniffmcp").joinpath("assets", f"raccoon-{name}.png").read_bytes()
    return "data:image/png;base64," + base64.b64encode(data).decode()


_CSS = """
:root{--bg:#f4f1ff;--card:#fff;--ink:#2a2140;--muted:#6b6385;--brand:#8b7be8;--lime:#b6e85c;
--bad:#e5484d;--line:#e6e0fb;--chip:#f1edff}
@media (prefers-color-scheme:dark){:root{--bg:#16121f;--card:#211b2e;--ink:#f2eefb;--muted:#a79fbd;
--brand:#a596ff;--line:#342b47;--chip:#2b2340}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px 16px;background:var(--bg);
color:var(--ink);font:16px/1.55 ui-rounded,"SF Pro Rounded","Nunito","Segoe UI",system-ui,sans-serif}
.card{width:100%;max-width:440px;background:var(--card);border:1px solid var(--line);border-radius:28px;
padding:28px 28px 22px;text-align:center;box-shadow:0 18px 50px -24px rgba(80,60,160,.45)}
.mascot{width:200px;max-width:70%;height:auto;border-radius:20px;background:#fff;padding:6px}
.word{font-weight:800;font-size:15px;letter-spacing:.2px;margin:14px 0 2px}
.word b{color:var(--brand)}
h1{font-size:26px;line-height:1.2;margin:6px 0 8px}
p{margin:6px 0;color:var(--muted)}
.chip{display:inline-block;margin:10px 0 4px;padding:6px 12px;border-radius:999px;background:var(--chip);
color:var(--ink);font:600 14px/1.3 ui-monospace,"SF Mono",Menlo,Consolas,monospace;word-break:break-all}
.ok h1::after{content:"";display:inline-block;width:10px;height:10px;margin-left:8px;border-radius:50%;
background:var(--lime);vertical-align:middle}
.bad h1{color:var(--bad)}
.err{margin:12px 0 0;padding:10px 12px;border-radius:14px;background:var(--chip);text-align:left;
font:13px/1.45 ui-monospace,"SF Mono",Menlo,Consolas,monospace;color:var(--ink);word-break:break-word}
code{font:600 14px ui-monospace,"SF Mono",Menlo,Consolas,monospace;background:var(--chip);
padding:2px 7px;border-radius:8px;color:var(--ink)}
.foot{margin-top:18px;padding-top:12px;border-top:1px dashed var(--line);font-size:12.5px;color:var(--muted)}
"""


def _page(kind: str, mascot: str, alt: str, title: str, body: str) -> bytes:
    doc = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="referrer" content="no-referrer">
<title>SniffMCP · {html.escape(title, quote=False)}</title><style>{_CSS}</style></head>
<body><main class="card {kind}">
<img class="mascot" src="{_mascot(mascot)}" alt="{html.escape(alt)}">
<div class="word">Sniff<b>MCP</b></div>
<h1>{html.escape(title, quote=False)}</h1>
{body}
<div class="foot">This page was served by SniffMCP on your own machine (127.0.0.1).</div>
</main></body></html>"""
    return doc.encode("utf-8")


def _host(server_url: str | None) -> str:
    return urlparse(server_url or "").netloc or (server_url or "")


def success_page(server_url: str | None = None) -> bytes:
    host = _host(server_url)
    chip = f'<div class="chip">{html.escape(host)}</div>' if host else ""
    return _page("ok", "all-clear", "Raccoon detective holding a checklist with every item ticked",
                 "You're logged in", f"""{chip}
<p>Head back to your terminal. The scan results are on their way.</p>
<p>SniffMCP only <b>lists</b> this server's tools. It never calls them, and it asked for read-only access.</p>
<p>You can close this tab.</p>""")


def error_page(error: str, description: str | None = None, server_url: str | None = None) -> bytes:
    host = _host(server_url)
    detail = html.escape(error) + (f": {html.escape(description)}" if description else "")
    retry = f"sniffmcp login {server_url}" if server_url else "sniffmcp login &lt;server&gt;"
    return _page("bad", "find-risks", "Raccoon detective holding up a warning sign",
                 "Login didn't go through", f"""{f'<div class="chip">{html.escape(host)}</div>' if host else ''}
<p>The server didn't grant access, so nothing was stored.</p>
<div class="err">{detail}</div>
<p style="margin-top:14px">To try again, run <code>{html.escape(retry) if server_url else retry}</code> in your terminal.</p>""")


def http_response(status: str, body: bytes) -> bytes:
    head = (f"HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n"
            f"Content-Security-Policy: {CSP}\r\nReferrer-Policy: no-referrer\r\nCache-Control: no-store\r\n"
            f"X-Content-Type-Options: nosniff\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n")
    return head.encode("ascii") + body
