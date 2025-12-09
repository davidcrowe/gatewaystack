
## Demos

| Command | Components | What it proves |
| ------- | ---------- | -------------- |
| `npm run demo:mcp` | Runs the MCP issuer (`demos/mcp-server` on :5051), the gateway in demo mode (:8080), and the MCP JSON-RPC surface. | 401→PRM→token handshake, `/protected/*` isolation, per-tool scopes, `/proxy` identity injection. |
| `npm run demo:apps` | Adds the ChatGPT Apps SDK-style connector on :5052 (`demos/chatgpt-connector`) while reusing the issuer and gateway. | Shows the same JWT/scope enforcement works for Apps SDK connectors. |

Both demos share the local issuer + JWKS hosted by `demos/mcp-server`. Mint reader/writer tokens with:

```bash
curl -s -X POST http://localhost:5051/mint \
  -H 'content-type: application/json' \
  --data '{"scope":"tool:read tool:write","sub":"demo-user"}'
```

See `demos/mcp-server/README.md` and `demos/chatgpt-connector/README.md` for the curl walkthroughs and troubleshooting tips.

---

## Demo mode env

Set these in `apps/gateway-server/.env` to enable local demos without Auth0:

```bash
DEMO_MODE=true
OAUTH_ISSUER_DEMO=http://localhost:5051/
OAUTH_AUDIENCE_DEMO=https://gateway.local/api
OAUTH_JWKS_URI_DEMO=http://localhost:5051/.well-known/jwks.json
OAUTH_SCOPES_DEMO=tool:read tool:write
ENABLE_TEST_ROUTES=true
```

With demo mode on you can run `npm run demo:*`, call `/protected/ping`, exercise `/proxy/*`, and run MCP JSON-RPC flows without touching Auth0.

--- 

## Connect to Claude (MCP)

If you’re using this gateway as an **MCP server** (e.g. Claude Desktop, Cursor, etc.), no code changes are required.
The gateway is **auth-initiator agnostic** — it simply validates RS256 tokens and enforces scopes, regardless of who started the OAuth flow.

### 1️⃣ Return 401 with Protected Resource Metadata (PRM) pointer

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="mcp", resource_metadata="https://<YOUR_GATEWAY>/.well-known/oauth-protected-resource"
Content-Type: application/json

{"error":"unauthorized","error_description":"Access token required"}
```

> The PRM URL tells the MCP client where to discover OAuth configuration for this resource.

### 2️⃣ Protected Resource Metadata (PRM) Example

Serve this JSON at `/.well-known/oauth-protected-resource`:

```json
{
  "resource": "https://<YOUR_GATEWAY>/mcp",
  "authorization_servers": ["https://<YOUR_AUTH_SERVER>/"],
  "scopes_supported": ["tool:read", "tool:write"]
}
```

| **Field**               | **Description**                           |
| ----------------------- | ----------------------------------------- |
| `resource`              | Identifier for this gateway’s MCP surface |
| `authorization_servers` | OAuth / OIDC issuer (e.g. Auth0, Okta)    |
| `scopes_supported`      | Scopes mapped to your route allowlist     |

### 3️⃣ Scopes → Routes (deny-by-default)

| **Scope**    | **Routes**         |
| ------------ | ------------------ |
| `tool:read`  | `GET /v1/tools/*`  |
| `tool:write` | `POST /v1/tools/*` |

Requests with a valid token but missing scope will receive **403 Forbidden**.

### 4️⃣ Redirect URIs (common MCP clients)

Register your client with the IdP and allow its redirect URI(s):

* **Claude Desktop/Web:** documented callback (e.g. `https://claude.ai/api/mcp/auth_callback`)
* **Cursor IDE:** their documented OAuth callback

If your IdP supports **Dynamic Client Registration (DCR)**, you can enable it instead of pre-registering.

### 5️⃣ Smoke Test
```bash
# No token → 401 + WWW-Authenticate header
curl -i https://<YOUR_GATEWAY>/protected

# Valid token with tool:read → 200
curl -i -H "Authorization: Bearer $TOKEN" https://<YOUR_GATEWAY>/protected

# Valid token, insufficient scope → 403
curl -i -H "Authorization: Bearer $TOKEN" https://<YOUR_GATEWAY>/writer-only
```
