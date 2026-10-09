"""OAuth-protected MCP server for tests: an in-memory authorization server (dynamic client
registration, PKCE, auto-approving /authorize) in front of one tool.

usage: python oauth_server.py <port>
"""
import secrets, sys, time

from mcp.server.auth.provider import (AccessToken, AuthorizationCode, AuthorizationParams, RefreshToken,
                                      construct_redirect_uri)
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.mcpserver import MCPServer
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

PORT = int(sys.argv[1])
BASE = f"http://127.0.0.1:{PORT}"


class InMemoryAS:
    def __init__(self):
        self.clients, self.codes, self.access, self.refresh = {}, {}, {}, {}

    async def get_client(self, client_id):
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        self.clients[client_info.client_id] = client_info

    async def authorize(self, client, params: AuthorizationParams) -> str:
        code = secrets.token_urlsafe(16)   # a real server would show a consent page here
        self.codes[code] = AuthorizationCode(
            code=code, scopes=params.scopes or [], expires_at=time.time() + 300, client_id=client.client_id,
            code_challenge=params.code_challenge, redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly, resource=params.resource)
        return construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state)

    async def load_authorization_code(self, client, authorization_code):
        return self.codes.get(authorization_code)

    def _issue(self, client_id, scopes, resource):
        at, rt = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        self.access[at] = AccessToken(token=at, client_id=client_id, scopes=scopes,
                                      expires_at=int(time.time()) + 3600, resource=resource)
        self.refresh[rt] = RefreshToken(token=rt, client_id=client_id, scopes=scopes, resource=resource)
        return OAuthToken(access_token=at, expires_in=3600, refresh_token=rt, scope=" ".join(scopes) or None)

    async def exchange_authorization_code(self, client, authorization_code):
        self.codes.pop(authorization_code.code, None)
        return self._issue(client.client_id, authorization_code.scopes, authorization_code.resource)

    async def load_refresh_token(self, client, refresh_token):
        return self.refresh.get(refresh_token)

    async def exchange_refresh_token(self, client, refresh_token, scopes):
        self.refresh.pop(refresh_token.token, None)
        return self._issue(client.client_id, scopes or refresh_token.scopes, refresh_token.resource)

    async def load_access_token(self, token):
        return self.access.get(token)

    async def revoke_token(self, token):
        self.access.pop(token.token, None)
        self.refresh.pop(token.token, None)


app = MCPServer("oauth-fixture", auth_server_provider=InMemoryAS(), auth=AuthSettings(
    issuer_url=BASE, resource_server_url=f"{BASE}/mcp", validate_token_resource=False,
    client_registration_options=ClientRegistrationOptions(enabled=True)))


@app.tool(description="Return the caller's private notes.")
def private_notes() -> str:
    return "secret"


if __name__ == "__main__":
    app.run("streamable-http", host="127.0.0.1", port=PORT)
