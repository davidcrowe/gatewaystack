# Gatewaystack — User-Scoped AI Model Trust & Governance

A **user-scoped AI gateway** for model trust and governance.

Gatewaystack solves the **user-scoped data access problem for AI models** — and extends it into a broader ecosystem for **trust, identity, policy, and governance** across agentic systems.

Gatewaystack is composed of modular packages that can **standalone** or as part of an *Agentic Control Plane*.

---

### 🧩 Trust Layer

| Package | Status | Description |
|----------|---------|-------------|
| **ai-auth-gateway** | ✅ *Published* | Verifies RS256 OAuth tokens, enforces per-tool scopes, rate-limits per user/tenant, and optionally proxies requests with user identity injection. |
| **ai-identity-gateway** | 🧭 *Roadmap* | Central identity resolver across agents and models. |
| **ai-access-gateway** | 🧭 *Roadmap* | Fine-grained access control for user-scoped data and model capabilities. |
| **ai-policy-gateway** | 🧭 *Roadmap* | Declarative policies for scopes, tools, and routes. |

---

### 🧠 Governance Layer

| Package | Status | Description |
|----------|---------|-------------|
| **ai-observability-gateway** | 🧭 *Roadmap* | Structured telemetry, metrics, and logs for model usage. |
| **ai-audit-gateway** | 🧭 *Roadmap* | Immutable audit trail of user and agent activity. |
| **ai-rate-limit-gateway** | 🧭 *Roadmap* | Centralized quota and rate-limiting across users and tenants. |
| **ai-cost-gateway** | 🧭 *Roadmap* | Tracks per-user or per-tenant model usage costs. |
| **ai-routing-gateway** | 🧭 *Roadmap* | Policy-based model routing and fallback orchestration. |

---

> **In short:** Gatewaystack provides the foundational trust and governance primitives every agentic ecosystem needs — starting with secure, user-scoped authentication and expanding into full lifecycle governance.


## User Authentication for AI Agents

The missing OAuth layer for ChatGPT Apps & Anthropic MCP — turn AI tools into **secure, user-scoped** integrations.
Enable ChatGPT and Claude to access **user-specific data** from your app safely.

**The Problem:** AI agents can’t access user data securely. OAuth for Apps SDK / MCP is confusing or broken out-of-the-box.
**The Solution:** A production-ready gateway that handles user auth (RS256), scopes, isolation, and optional DCR.

```typescript
// Before: Everyone sees everyone's data (🚨)
app.get('/calendar', async (_req, res) => {
  const events = await getAllEvents();
  res.json(events);
});

// After: User-scoped by default (✅)
// The gateway injects user identity; your app filters safely.
app.get('/calendar', async (req, res) => {
  const userId = req.headers['x-user-id'] as string;
  const events = await getUserEvents(userId);
  res.json(events);
});
```

**Works with:** ChatGPT Apps SDK • Anthropic MCP • Auth0
Drop it between your backend and ChatGPT — no SDK modification needed.

Turn Apps SDK / MCP connectors into user-scoped, Auth0-secured calls to your backend or Firestore.
Handles **RS256 JWTs**, audience/issuer checks, per-tool scopes, and optional **DCR** client promotion.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)
![Cloud Run](https://img.shields.io/badge/Cloud%20Run-ready-4285F4)
![Auth0](https://img.shields.io/badge/Auth0-RS256-orange)
[![MCP/Auth Conformance](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/OWNER/REPO/main/docs/conformance.json)](./docs/conformance.json)
[![Parity](https://github.com/OWNER/REPO/actions/workflows/parity.yml/badge.svg)](https://github.com/OWNER/REPO/actions/workflows/parity.yml)

> **Conformance summary**  
> Verified against Apps SDK / MCP OAuth 2.1 + RS256 flow.  
> - ✅ JWT validation (iss/aud/sub/exp/nbf)  
> - ✅ Scope allowlist / deny-by-default  
> - ✅ Expiry handling  
> - ✅ Health & protected resource endpoints  
> - *Last verified: 2025-10-31 (gatewaystack v0.1.0)*

**Quick links:**

* ▶️ [Quickstart (10 minutes)](#2-clone--install)
* 🔐 [Auth0 setup](#3-minimal-auth0-setup-10-minutes)
* 🧩 [Auth0 Post-Login Action for ChatGPT](#31-auth0-post-login-action-for-chatgpt-connectors)
* 📡 [Auth0 DCR / log stream helper](#12-dcr-webhook-optional)
* 🤝 [Connect to ChatGPT / Claude (MCP)](#9-proxy-mode-with-user-injection)
* 🩺 [Health & protected-resource metadata](#7-health--basic-smoke-tests)
* 🛡️ [Security defaults](#18-production-checklist)
* 🆘 [Troubleshooting](#13-troubleshooting)

---

## Demos

Spin up reference demos that validate user-scoped OAuth end-to-end.

### MCP (Claude / IDEs)
```bash
npm run demo:mcp
```
This runs:
- Issuer/PRM/JWKS on `:5051`
- Gateway in demo mode on `:8080`
- Minimal MCP server on `:5051/mcp/`

See `demos/mcp-server/README.md` for curl commands and expected 200/403/401 outcomes.

### ChatGPT Apps SDK
```bash
npm run demo:apps
```

This runs:
- Issuer/PRM/JWKS on `:5051`
- Gateway in demo mode on `:8080`
- Apps SDK connector on `:5052/apps/`

See `demos/chatgpt-connector/README.md` to verify read/write behavior with scopes.

```json
{
  "scripts": {
    "demo:mcp": "npm-run-all -p demo:issuer demo:gateway demo:mcp-server",
    "demo:apps": "npm-run-all -p demo:issuer demo:gateway demo:apps-server",
    "demo:issuer": "npm run -w @gatewaystack/demo-mcp-server dev",
    "demo:gateway": "DEMO_MODE=true npm run -w @gatewaystack/gateway-server dev",
    "demo:mcp-server": "npm run -w @gatewaystack/demo-mcp-server dev",
    "demo:apps-server": "npm run -w @gatewaystack/demo-chatgpt-connector dev"
  }
}
```

--- 

### Why user-scoped access matters

AI agents are powerful—yet useless without *safe* access to real data.
The challenge: **How do you let ChatGPT read *my* calendar without exposing *everyone’s* calendar?**

**Without user authentication**

* ❌ Shared API keys (everyone sees everything)
* ❌ Fails audits and compliance (SOC 2 / HIPAA)

**With this gateway**

* ✅ OAuth login per user (RS256)
* ✅ Per-user isolation by default
* ✅ Audit trails & rate limits
* ✅ Production in minutes, not weeks

---

## Gatewaystack — Quickstart & Parity Guide

This guide walks you through spinning up the gateway, validating parity with the original `openai-auth0-gateway`, and deploying to Cloud Run.

---

### 0. What You Get (Feature Surface)

- ✅ **RS256 JWT Verification** via JWKS (issuer, audience, exp, nbf, sub checks)
- ✅ **Per-tool scope enforcement** (deny-by-default; 401/403 outcomes)
- ✅ **Protected resource endpoint** for smoke tests
- ✅ **Proxy mode** with user injection (`X-User-Id` and/or `?userId=…`) and response post-filtering
- ✅ **Rate limiting** (user/tenant aware)
- ✅ **Health endpoints** (`/health`, `/health/auth0`)
- ✅ *(Optional)* **DCR webhook** to auto-promote new OAuth clients from Auth0 logs
- ✅ **Echo test servers** to validate proxy/header injection

> The above mirrors the original **openai-auth0-gateway** contract, now refactored into modular packages:
> `auth-*`, `policy-*`, `rate-limit-*`, `routing-*`, and `observability-*`, with the main app at `apps/gateway-server`.

---

### 1. Prerequisites

- Node.js **20+** (or 22)
- npm **10+** (or pnpm 9)
- An **Auth0 tenant** (or equivalent OIDC provider issuing RS256 access tokens)
- *(Optional)* Google Cloud SDK for Cloud Run deploys

---
### 2. Clone & Install

```bash
git clone <your-repo-url> gatewaystack
cd gatewaystack

# Install all workspaces
npm install
```

---

### 3. Minimal Auth0 Setup (≈10 minutes)

#### Create an API (Auth0 Dashboard → Applications → APIs)

* **Name:** `Gateway API`
* **Identifier (Audience):** `https://gateway.local/api` *(any HTTPS URI string)*
* **Signing algorithm:** `RS256`
* Enable **RBAC** and **Add Permissions in the Access Token**

#### Define permissions/scopes (examples)

* `tool:read`
* `tool:write`

#### Create an Application

Create a **Regular Web App** or **SPA** to obtain tokens during development.

#### Well-Known Issuer

Your issuer will be:

```
https://<TENANT>.region.auth0.com/
```

#### (Optional) Management API client (for DCR webhook)

Create a **Machine-to-Machine** application with scopes:

```
read:clients update:clients read:connections update:connections read:logs
```

#### Get a dev access token

* From your app’s Auth0 **Test** tab or via a quick PKCE flow.
* Ensure the token’s **audience** matches your API identifier and includes the scopes you want to test (e.g., `tool:read`).

---

### 3.1 Auth0 Post-Login Action for ChatGPT connectors

> **Only required if you are using ChatGPT Apps SDK.**  
> If you’re only using the gateway with your own OAuth client or MCP, you can skip this section.

If you are using this gateway with **ChatGPT Apps SDK**, you must add a Post-Login Action so that:

- The access token audience (`aud`) is forced to your API Identifier.
- The token is issued as an **RS256 JWS** (3-part JWT), not an encrypted JWE or opaque token.
- All scopes required by your tools are present on the token.

High-level steps:

1) Go to **Actions → Library → + Create Action** and name it `auto-assign-openai-connector-role`.  
2) Choose **Trigger:** Login / Post Login.  
3) Paste the code from `docs/auth0/chatgpt-post-login-action.js`.  
4) Add secrets:  
   - `API_AUDIENCE` → your Auth0 API Identifier (e.g., `https://inner.app/api`)  
   - `CONNECTOR_ROLE_ID` → (optional) Role ID to auto-assign to connector users  
5) Click **Deploy**.  
6) Attach it to the flow: **Actions → Flows → Login (Post Login)**, drag the Action between **Start** and **Complete**, then click **Apply**.

For a full walkthrough, screenshots, and troubleshooting checklist, see `docs/auth0/chatgpt-post-login-action.md`.

### 4. Configure the Gateway

Copy the example env and fill in values:

```bash
cp apps/gateway-server/.env.example apps/gateway-server/.env
```

Set at minimum:

```
# === Auth ===
AUTH_ISSUER=https://<TENANT>.auth0.com/
AUTH_AUDIENCE=https://gateway.local/api
AUTH_JWKS_URI=https://<TENANT>.auth0.com/.well-known/jwks.json
AUTH_ENFORCE_ALG=RS256

# === CORS (dev) ===
CORS_ORIGIN=http://localhost:5173,http://localhost:3000

# === Scopes / policy ===
REQUIRED_SCOPES_READ=tool:read
REQUIRED_SCOPES_WRITE=tool:write

# === Rate limiting (dev defaults) ===
RATE_LIMIT_WINDOW_MS=60000
RATE_LIMIT_MAX=60

# === Proxy mode (optional) ===
PROXY_TARGET=http://localhost:3333   # the echo server you'll run below
PROXY_INJECT_HEADER=X-User-Id
PROXY_INJECT_QUERY=userId

# === Observability/logging (dev) ===
LOG_LEVEL=info

# === DCR webhook (optional) ===
WEBHOOK_SHARED_SECRET=devsecret
AUTH0_MGMT_CLIENT_ID=...
AUTH0_MGMT_CLIENT_SECRET=...
AUTH0_TENANT_DOMAIN=<TENANT>.auth0.com
```

> If you keep parity with the original repo’s env names, users can drop in their existing `.env` with minimal edits.

---

### 5. Start the Test Backends (Echo Servers)

These help prove proxy + header injection:

```bash
# Echo server that returns headers, query, and body
npm run -w @gatewaystack/echo-server dev
# default: http://localhost:3333
```

---

### 6. Run the Gateway (dev)

```bash
npm run -w apps/gateway-server dev
# default: http://localhost:8080  (matches your current logs)

```

You should see logs indicating JWKS warmup and route registration.

---

### 7. Health & Basic Smoke Tests

```bash
# Health (served by healthRoutes at /health)
curl -s http://localhost:8080/health | jq .

# Auth0 checks (JWKS reachability, mgmt token if set)
curl -s http://localhost:8080/health/auth0 | jq .

# Protected resource metadata (expect 401 without token + WWW-Authenticate)
curl -i http://localhost:8080/.well-known/oauth-protected-resource
```

When called **without** a token, you should see a `401` with a `WWW-Authenticate` header that points ChatGPT / MCP to this URL as the **Protected Resource Metadata (PRM)** endpoint.

When called **with** a valid token, you should see JSON similar to:

```json
{
  "authorization_servers": ["https://<TENANT>.auth0.com/"],
  "scopes_supported": [
    "openid",
    "email",
    "profile",
    "tool:read",
    "tool:write"
  ],
  "resource": "https://gateway.local/api"
}
```

Where:

- `authorization_servers` tells the client which issuer(s) can mint access tokens.
- `scopes_supported` is derived from your configured tool scopes (`TOOL_SCOPES` → `REQUIRED_SCOPES` in the gateway).
- `resource` is your API Identifier / audience (`AUTH_AUDIENCE` / `OAUTH_AUDIENCE`).

When you add a new tool scope in `TOOL_SCOPES`, the gateway automatically:

- Updates `REQUIRED_SCOPES`
- Exposes it in `scopes_supported`
- Includes it in the `scope=` parameter of the `WWW-Authenticate` header
- Ensures the client grant includes the new scope (if using the Auth0 DCR helper)

**Expected:**

* `/health` → `{ ok: true, ... }`
* `/health/auth0` → issuer/audience OK, JWKS reachable
* Protected resource → **401** w/o token, **200** w/ token

---

### 8. Scope/RBAC Checks (Parity)

> 💡 **Tip:** You'll need two different Auth0 tokens to see the scope-based 403 in action.  
> - `$READER` → a token minted with only `tool:read`  
> - `$WRITER` → a token minted with both `tool:read tool:write`  
> If you reuse the same token for both, you'll get `200 OK` on every call.


```bash
# Endpoint that requires read scope
curl -i \
  -H "Authorization: Bearer $READER" \
  -H "X-Required-Scope: tool:read" \
  http://localhost:8080/__test__/echo

# Endpoint that requires write scope (should fail for Reader)
curl -i -X POST \
  -H "Authorization: Bearer $READER" \
  -H "X-Required-Scope: tool:write" \
  http://localhost:8080/__test__/echo
# expect 403

# Same endpoint with Writer (should succeed)
curl -i -X POST \
  -H "Authorization: Bearer $WRITER" \
  -H "Content-Type: application/json" \
  -H "X-Required-Scope: tool:write" \
  --data '{"msg":"hello"}' \
  http://localhost:8080/__test__/echo
# expect 200 + echo body
```

> `__test__/echo` is provided by `apps/gateway-server/src/routes/testEcho.ts`. Adjust if you renamed it; any protected route will do.

---

### 9. Proxy Mode with User Injection

Hit a proxied path that forwards to the echo server:

```bash
# Without token: expect 401 (gateway blocks; backend never sees request)
curl -i http://localhost:8787/proxy/echo

# With token (READER or WRITER): expect 200 and the echo payload
curl -s -H "Authorization: Bearer $READER" \
  http://localhost:8787/proxy/echo?foo=bar | jq .
```

**Confirm in the echo response:**

* `headers["x-user-id"] === <sub from token>` (or whatever you set via `PROXY_INJECT_HEADER`)
* `query.userId === <sub>` if `PROXY_INJECT_QUERY=userId` is configured
* Your original `foo=bar` query remains intact

---

### 10. Rate Limiting (Quick Verification)

```bash
export RATE_LIMIT_MAX=5
for i in {1..20}; do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "Authorization: Bearer $READER" \
    "http://127.0.0.1:8080/protected/ping" &
done; wait | sort | uniq -c

```

You should see **429** responses once the `RATE_LIMIT_MAX` per window is exceeded.

---

### Deploys & Admin UI

Minimal local flow is covered here. Opinionated deploy guides (Cloud Run, Render, etc.) and the optional Admin UI will live in /docs soon. For now, any Node/Express deploy that forwards your env vars will work.

---

### 11. Conformance Tests (Scripted)

A tiny parity harness is included at `apps/gateway-server/tests/basic.test.ts` (and `tests/basic.test.js` for JS). You can run:

```bash
# Dev
npm test -w apps/gateway-server
# Or run a specific parity script if provided
```

If you prefer a domain-to-domain comparison (old vs new), drop in a simple script like `tests/compat/basic.test.ts` that calls the same endpoints on two base URLs and asserts identical statuses/JSON shape. *(Ask if you want a prebuilt template.)*

---

### 12. DCR Webhook (Optional)

> **When to use this:** If you want new ChatGPT connectors to **auto-register** in Auth0 and immediately gain access to your API with the correct grant types, Google connection, and scopes, enable the DCR webhook.

This endpoint is typically wired as an Auth0 **Log Stream** target that listens for `/oidc/register` events (Dynamic Client Registration) and then:

- Promotes the new client to a public `regular_web` app with PKCE.
- Enables the `google-oauth2` connection for that client.
- Ensures a client grant exists for your API (`AUTH_AUDIENCE`) with all `REQUIRED_SCOPES`.

For a detailed walkthrough and environment variable reference (`MGMT_DOMAIN`, `MGMT_CLIENT_ID`, `MGMT_CLIENT_SECRET`, `LOG_WEBHOOK_SECRET`, `GOOGLE_CONNECTION_NAME`, `OAUTH_AUDIENCE`), see `docs/auth0/dcr-log-webhook.md`.

If you want the same DCR “promotion” flow as the original:

**Auth0 → Monitoring → Streams → Webhook**

```
POST https://<your-gateway-domain>/webhooks/auth0/logs
X-Webhook-Secret: <WEBHOOK_SHARED_SECRET>
```

In your `.env`, set the Management API client creds & `WEBHOOK_SHARED_SECRET`.

Trigger a client registration event (or simulate via Auth0 log events).

Check `/health/auth0` — you should see a **recent webhook last-seen** timestamp and successful management calls in your logs.

---

### 13. Troubleshooting

> **Using Auth0 + ChatGPT?** For Auth0-specific issues (Post-Login Actions, JWE vs JWS tokens, scopes not showing up, etc.), see `docs/auth0/chatgpt-post-login-action.md` → “Troubleshooting checklist”.

**401 with valid token**

* Check `AUTH_AUDIENCE` matches the token `aud`
* Check `AUTH_ISSUER` matches token `iss` and the JWKS URL resolves
* Ensure **RS256** is used; HS256 will be rejected when `AUTH_ENFORCE_ALG=RS256=true`

**403 on write**

* Your token likely lacks `tool:write`; confirm “Add Permissions in the Access Token” is enabled on the API

**Proxy not injecting user**

* Verify `PROXY_TARGET` is reachable
* Confirm `PROXY_INJECT_HEADER` / `PROXY_INJECT_QUERY` are set and your route is going through the proxy handler

**Rate limit never triggers**

* Lower `RATE_LIMIT_MAX` and ensure identifier (user/tenant) is parsed from the token’s `sub` / `org_id`

---

### 14. What’s Different vs the Original?

Code is modularized into packages:

* `auth-*` (JWT/JWKS and claims validation)
* `policy-*` (scope & RBAC)
* `routing-*` (proxy, header/query injection)
* `rate-limit-*` (counters & windows)
* `observability-*` (structured logs / metrics)

The runtime behavior and endpoints above preserve the original contract so existing users can run the gateway as a **standalone**.

---

### 15. Production Checklist

* ✅ RS256 enforced; JWKS timeout & caching tuned
* ✅ Strict CORS (exact origins)
* ✅ Deny-by-default policies per route/tool
* ✅ Rate-limit per user/tenant with sane ceilings
* ✅ Logs redact PII; audit fields: `{sub, tool, path, decision, latency}`
* ✅ Health probes hooked into your orchestrator
* ✅ *(Optional)* DCR webhook secret rotated; Mgmt API scopes minimal


## 🧩 MCP Quick Connect (OAuth 2.1, User-Scoped)

If you’re using this gateway as an **MCP server** (e.g. Claude Desktop, Cursor, etc.), no code changes are required.
The gateway is **auth-initiator agnostic** — it simply validates RS256 tokens and enforces scopes, regardless of who started the OAuth flow.

---

### 1️⃣ Return 401 with Protected Resource Metadata (PRM) pointer

```http
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Bearer realm="mcp", resource_metadata="https://<YOUR_GATEWAY>/.well-known/oauth-protected-resource"
Content-Type: application/json

{"error":"unauthorized","error_description":"Access token required"}
```

> The PRM URL tells the MCP client where to discover OAuth configuration for this resource.

---

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

---

### 3️⃣ Scopes → Routes (deny-by-default)

| **Scope**    | **Routes**         |
| ------------ | ------------------ |
| `tool:read`  | `GET /v1/tools/*`  |
| `tool:write` | `POST /v1/tools/*` |

Requests with a valid token but missing scope will receive **403 Forbidden**.

---

### 4️⃣ Redirect URIs (common MCP clients)

Register your client with the IdP and allow its redirect URI(s):

* **Claude Desktop/Web:** documented callback (e.g. `https://claude.ai/api/mcp/auth_callback`)
* **Cursor IDE:** their documented OAuth callback

If your IdP supports **Dynamic Client Registration (DCR)**, you can enable it instead of pre-registering.

---

### 5️⃣ Smoke Test

| **Case**               | **Command**                                                                    | **Expected**                                                 |
| ---------------------- | ------------------------------------------------------------------------------ | ------------------------------------------------------------ |
| **No token**           | `curl -i https://<YOUR_GATEWAY>/protected`                                     | `401 Unauthorized` with `WWW-Authenticate` header + PRM link |
| **Valid token**        | `curl -i -H "Authorization: Bearer $TOKEN" https://<YOUR_GATEWAY>/protected`   | `200 OK` if `scope=tool:read`                                |
| **Insufficient scope** | `curl -i -H "Authorization: Bearer $TOKEN" https://<YOUR_GATEWAY>/writer-only` | `403 Forbidden`                                              |

---

### ⚙️ Implementation Notes

* Always validate `iss`, **pin `aud`**, enforce `alg = RS256`, and honor `exp`/`nbf`.
* Keep tokens **short-lived**; rotate/revoke via your IdP.
* Use gateway **identity injection** (e.g. `X-User-Id`) to pass user context downstream — never expose upstream API keys to the LLM client.

---