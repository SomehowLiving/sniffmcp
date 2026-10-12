# Servers that need a login (OAuth)

Many remote MCP servers require OAuth before they'll list their tools. SniffMCP can log in to them
itself, so their descriptions get checked too.

```bash
sniffmcp login https://mcp.example.com/mcp    # or the name of a server in your client config
sniffmcp fleet --login                        # log in to each installed server that needs it
sniffmcp logins                               # list stored logins
sniffmcp logout https://mcp.example.com/mcp
```

## What happens when you log in

1. SniffMCP discovers the server's authorization server from its protected-resource metadata.
2. It registers **itself** as an OAuth client (dynamic client registration). It never reads or reuses
   your AI client's tokens.
3. It opens your browser for the normal consent screen and receives the code on a one-shot callback
   on `127.0.0.1`, protected with PKCE.
4. The tokens are stored in `~/.sniffmcp/oauth/`, readable by your user only, and never printed.

Later `scan`, `fleet` and `watch` runs reuse the login and refresh it when needed.

## Read-only by design

A scanner only *lists* tools, so SniffMCP asks for **read scopes only**. The MCP Python SDK otherwise
requests every scope a server advertises, including write scopes; SniffMCP filters those out however
the SDK sets them. (The SDK behaviour is tracked upstream in
[python-sdk#2317](https://github.com/modelcontextprotocol/python-sdk/issues/2317).)

If a server rejects a partial scope list, override it for that login:

```bash
SNIFFMCP_OAUTH_SCOPE=all sniffmcp login https://mcp.example.com/mcp           # everything advertised
SNIFFMCP_OAUTH_SCOPE="profile.read projects.read" sniffmcp login https://…     # an exact list
```

Scans never call a tool with your login. The crawler, `--no-launch` and CI runs never use stored logins.

## When login isn't possible

Some servers don't allow dynamic client registration (or a client metadata document), so third-party
tools can't log in. For those, pass a token yourself in the config's `headers`:

```json
{"url": "https://mcp.example.com/mcp", "headers": {"Authorization": "Bearer ${MY_TOKEN}"}}
```

`${VAR}` references are expanded from your environment and never flagged as leaked secrets.

## WSL

On WSL, the browser runs on Windows and reaches the callback through WSL's localhost forwarding.
Windows reserves some port ranges (Hyper-V/WSL) that can never be forwarded, so SniffMCP picks callback
ports from 20000–32767, skips the reserved ranges, and re-registers a stored login whose port became
reserved.
