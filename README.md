# GatewayStack — Agentic Control Plane for User-Scoped AI Governance

An open-source control plane that makes AI agents **enterprise-ready** by enforcing user-scoped identity, policy, and audit trails on every model call.

**The problem:**  

AI models and user data need each other... but can't safely connect. 

- Users want AI to access *their* data (ChatGPT reading *my* calendar). 
- Enterprises want to control *who* can use AI models (only doctors can use medical models, only employees can send sensitive prompts). 

Both require **cryptographic proof of user identity** tied to every AI request... but AI platforms authenticate users on their side while your backend has no verified identity to enforce policies, filter data, or log actions.

**Gatewaystack solves this.**  

Drop it between AI clients (ChatGPT, Claude, MCP) and your backend. It validates OAuth tokens, enforces scopes, and injects verified identity—so you can safely answer the two questions that matter most:

1. **Who** did what, with **which** data, via **which** model?
2. Was it **authorized**, **bounded**, and **logged** under policy?

Every AI request flows through six governance checkpoints:
> **Identified → Transformed → Validated → Constrained → Routed → Audited**

---

### The Three-Party Problem

Modern AI apps are really **three-party systems**:

**👤 The User** — a real human with identity, roles, and permissions  
**🤖 The LLM** — a model acting on their behalf (ChatGPT, Claude)  
**🔒 Your Backend** — the trusted data and tools the model needs to access  

These three parties all influence each other, but they don’t share a common, cryptographically verified identity layer.

**The gap:** The LLM knows who the user is (they logged into ChatGPT). Your backend doesn't. So it can't:
- Filter data per-user (*"show me my calendar"* → returns everyone's calendar ❌)
- Enforce per-user policies (*"only doctors use medical models"* → anyone can ❌)
- Audit by user (*"who made this query?"* → can't answer ❌)

**Without a unifying identity layer, you get:**
- ❌ Shared API keys (everyone sees everything, or no one sees anything)
- ❌ No enforcement ("who can use which models for what")
- ❌ No audit trail (can't prove compliance)
- ❌ Enterprises block AI access entirely (too risky)

This instability across user ↔ LLM ↔ backend is what Gatewaystack calls the **Three-Party Problem**. 

It shows up in two directions:

---


### Direction 1: Enterprises controlling who can use which models and tools
*"How do I ensure only **licensed doctors** use medical models, only **analysts** access financial data, and **contractors** can't send sensitive prompts?"*

> user ↔ backend ↔ LLM

**Without Gatewaystack:**
```typescript
app.post('/chat', async (req, res) => {
  const { model, prompt } = req.body;
  const response = await openai.chat.completions.create({
    model, // ❌ Anyone can use gpt-4-medical
    messages: [{ role: 'user', content: prompt }]
  });
  res.json(response);
});
```

**With Gatewaystack:**
```typescript
app.post('/chat', async (req, res) => {
  const userId = req.headers['x-user-id'];
  const userRole = req.headers['x-user-role']; // "doctor", "analyst", etc.
  const userScopes = req.headers['x-user-scopes']?.split(' ') || [];
  
  // Gateway already enforced: only doctors with medical:write can reach here
  const response = await openai.chat.completions.create({
    model: req.body.model,
    messages: [{ role: 'user', content: req.body.prompt }],
    user: userId // OpenAI audit trail
  });
  res.json(response);
});
```

**Gateway policy:**
```json
{
  "gpt-4-medical": {
    "requiredRoles": ["doctor", "physician_assistant"],
    "requiredScopes": ["medical:write"]
  }
}
```

The gateway enforces role + scope checks **before** forwarding to your backend. If a nurse tries to use `gpt-4-medical`, they get `403 Forbidden`.

---

### Direction 2: Users accessing their own data via AI
*"How do I let ChatGPT read **my** calendar without exposing **everyone's** calendar?"*

> user ↔ LLM ↔ backend

**Without Gatewaystack:**
```typescript
app.get('/calendar', async (_req, res) => {
  const events = await getAllEvents(); // ❌ Everyone sees everything
  res.json(events);
});
```

**With Gatewaystack:**
```typescript
app.get('/calendar', async (req, res) => {
  const userId = req.headers['x-user-id']; // ✅ Verified by gateway
  const events = await getUserEvents(userId);
  res.json(events);
});
```

The gateway validates the OAuth token, extracts the user identity, and injects `X-User-Id` — so your backend can safely filter data per-user.

---

### Why Both Directions Matter

**Without solving the Three-Party Problem, you can't:**
- Filter data per-user (Direction 1: everyone sees everything)
- Enforce "who can use which models" (Direction 2: no role-based access)
- Audit "who did what" (compliance impossible)
- Rate limit per-user (shared quotas get exhausted)
- Attribute costs (can't charge back to teams/users)

**Gatewaystack solves both** by binding cryptographic user identity to every AI request:

* ✅ OAuth login per user (RS256 JWT, cryptographic identity proof)
* ✅ Per-user / per-tenant data isolation by default
* ✅ Deny-by-default authorization (scopes per tool/model/role)
* ✅ Immutable audit trails (who, what, when, which model)
* ✅ Rate limits & spend caps (per user/team/org)
* ✅ Drop-in between AI clients and your backend (no SDK changes)

Gatewaystack is composed of modular packages that can run **standalone** or as a cohesive **six-layer pipeline** for complete AI governance.

## Repository layout

| Path | Highlights |
| ---- | ---------- |
| `apps/gateway-server` | Express reference server wiring all six governance layers, `/protected/*` samples, demo/test routes, and a ready-to-build Docker image. |
| `apps/admin-ui` | Minimal Vite/React dashboard that polls `/health` so you can monitor the gateway while iterating. |
| `packages/` | Publishable packages for each layer plus helpers like `compat`, `request-context`, and `integrations`. |
| `demos/` | Working MCP issuer + ChatGPT Apps SDK connectors that mint demo JWTs and exercise the gateway. |
| `tools/` | Supporting utilities (echo server, mock tool backend, Cloud Run deploy helper, smoke harnesses). |
| `tests/` | Vitest entry points and placeholder smoke tests for parity. |
| `docs/` | Auth0 walkthroughs, conformance output, endpoint references, troubleshooting notes. |

### Package breakdown

- `@gatewaystack/identifiabl` – **Trust & Identity Binding.** Express middleware that verifies RS256 JWTs (via `jose`), enforces `iss`/`aud`, and attaches a canonical `req.user` for downstream policy, routing, and audit.

- `@gatewaystack/transformabl` – **Content Safety & Normalization.** Request/response normalization hook. Currently a no-op, reserved for redaction/classification/safety transforms that run *before* authorization and routing.

- `@gatewaystack/validatabl-core` / `@gatewaystack/validatabl` – **Authorization & Policy Enforcement.** Scope utilities plus Express helpers (e.g. `requireScope`) and the Protected Resource Metadata `.well-known` route. Enforces deny-by-default, fine-grained access to tools and models.

- `@gatewaystack/limitabl` – **Spend Controls & Resource Governance.** Rate limiting keyed on `sub`/`org_id` (falling back to IP) to prevent runaway agents, abuse, and unbounded cost at the user/tenant level.

- `@gatewaystack/proxyabl` – **Execution Control & Identity-Aware Routing.** Tool gateway + proxy router that:
  - Serves PRM/OIDC metadata for OAuth 2.1 / MCP / Apps SDK
  - Enforces scope-to-tool mappings (`TOOL_SCOPES_JSON`)
  - Injects verified identity into headers/queries (e.g. `X-User-Id`)
  - Hosts Auth0 integration points for log streams / DCR

- `@gatewaystack/explicabl` / `@gatewaystack/explicabl-core` – **Runtime Audit & Conformance.** Read-only on the RequestContext, write-only to external systems. Health endpoints, log/webhook handlers, and the conformance reporter (`saveReport.ts`) that emit correlated events to SIEM/observability stacks without blocking the critical path.

- `@gatewaystack/compat` – **Interop & Parity Harness.** Legacy/test router that mirrors the original `/echo` shape for quick interoperability and regression testing.

- `@gatewaystack/request-context`, `@gatewaystack/integrations`, and additional `*-core` folders – Shared types, RequestContext helpers, and staging areas for upcoming connectors as the Agentic Control Plane expands.

---

### Reference server (apps/gateway-server)

`apps/gateway-server/src/app.ts` composes the six governance layers in order:

1. Public **Protected Resource Metadata** via `protectedResourceRouter`.
2. `/protected/*` pipeline → `identifiabl` (JWT) → `limitabl` → `transformabl`.
3. Sample handlers (`GET /protected/ping`, `POST /protected/echo`) with `requireScope("tool:write")`.
4. `toolGatewayRouter` for PRM/OIDC well-knowns, MCP/Apps JSON-RPC, `/proxy`, and the Auth0 log webhook.
5. `explicablRouter` for `/health`, `/health/auth0`, and `/webhooks/auth0`.

Toggles worth noting:

- `DEMO_MODE=true` swaps in `OAUTH_*_DEMO` overrides so demos can mint JWTs locally.
- `ENABLE_TEST_ROUTES=true` + `TOOL_SCOPE_ALLOWLIST_JSON` expose `/__test__/echo` for conformance runs.
- `RATE_LIMIT_WINDOW_MS` / `RATE_LIMIT_MAX` tune limitabl without editing TypeScript.
- `.env.example` plus `apps/gateway-server/.env.example` enumerate every knob.

---
### Admin UI (apps/admin-ui)

`npm run dev:admin` launches a tiny Vite/React panel (`apps/admin-ui/src/App.tsx`) that fetches `/health` and renders the JSON so you can keep gateway status visible while iterating.

---

### Core governance layers

Every request flows through the same six-layer composable pipeline:

| Layer        | Status | Purpose                                                                      |
| ------------ | ------ | ---------------------------------------------------------------------------- |
| **identifiabl**  | ✅     | **Foundational Trust & Identity Binding** — verifies RS256 JWTs, pins issuer/audience, and establishes the canonical subject for downstream authorization and audit. |
| **transformabl** | ⚪     | **Content Safety Preprocessing & Risk Mitigation** — normalizes, redacts, or classifies inputs/outputs before policy and routing are applied. |
| **validatabl**   | ✅     | **Authorization & Policy Enforcement** — deny-by-default, scope-driven access to protected resources, tools, and models. |
| **limitabl**     | ✅     | **Rate & Spend Governance** — throttles per user/tenant to prevent runaway agents and unbounded cost. |
| **proxyabl**     | 🧩     | **Execution Control & Identity-Aware Routing** — routes calls to the right tool/model backend, injects verified identity, and presents OAuth/PRM metadata. |
| **explicabl**    | ⚪     | **Accountability & Runtime Audit** — emits immutable, correlated events to your SIEM/observability stack and exposes health/conformance endpoints. |

Drop it between AI clients and your backend — no SDK modification needed. Handles **RS256 JWTs**, audience/issuer checks, per-tool scopes, role-based policies, and optional **DCR** client promotion.

---

### Conformance summary

Verified against Apps SDK / MCP OAuth 2.1 + RS256 flow.  
- ✅ JWT validation (iss/aud/sub/exp/nbf)  
- ✅ Scope allowlist / deny-by-default  
- ✅ Expiry handling  
- ✅ Health & protected resource endpoints  

---

### Quick links

* ▶️ [Quickstart (10 minutes)](#quickstart-10-minutes)
* 🔐 [Identity Provider Setup](#identity-provider-setup)
  * [Auth0](#auth0-setup-10-minutes) (quickest to get started)
  * [Okta](#okta-setup) (coming soon)
  * [Entra ID](#entra-id-setup) (coming soon)
* 🤝 [Connect to ChatGPT / Claude (MCP)](#mcp-quick-connect-oauth-21-user-scoped)
* 🩺 [Health & protected-resource metadata](#health--basic-smoke-tests)
* 🛡️ [Production Checklist](#production-checklist)
* 🆘 [Troubleshooting](#troubleshooting)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)
![Cloud Run](https://img.shields.io/badge/Cloud%20Run-ready-4285F4)
![Auth0](https://img.shields.io/badge/Auth0-RS256-orange)
[![MCP/Auth Conformance](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fdavidcrowe%2Fgatewaystack%2Fmain%2Fdocs%2Fconformance.json&query=$.version&label=MCP%2FAuth%20Conformance)](https://github.com/davidcrowe/gatewaystack/tree/main/docs/conformance.json)



## Use Cases

### Healthcare SaaS — HIPAA-Compliant AI Diagnostics

A platform with 10,000+ doctors needs to ensure every AI-assisted diagnosis is tied to the licensed physician who requested it, with full audit trails for HIPAA and internal review.

**Before Gatewaystack:** All AI calls run through a shared OpenAI key — impossible to prove *which physician* made *which request*.

**With Gatewaystack:** 
- `identifiabl` binds every request to a verified physician (`user_id`, `org_id` = clinic/hospital)
- `validatabl` enforces `role:physician` and `scope:diagnosis:write` per tool
- `explicabl` emits immutable audit logs with the physician's identity on every model call

**Result:** User-bound, tenant-aware, fully auditable AI diagnostics.

---

### Enterprise Copilot — Per-Employee Policy Enforcement

A global company rolls out an internal copilot that can search Confluence, Jira, Google Drive, and internal APIs. Employees authenticate with SSO (Okta / Entra / Auth0), but the copilot calls the LLM with a shared API key.

**Before Gatewaystack:** Security teams can't enforce "only finance analysts can run this tool" or audit which employee triggered which action.

**With Gatewaystack:**
- `identifiabl` binds the copilot session to the employee's SSO identity (`sub` from Okta)
- `validatabl` enforces per-role tool access ("legal can see these repos, not those")
- `limitabl` applies per-user rate limits and spend caps
- `explicabl` produces identity-level audit trails for every copilot interaction

**Result:** Full identity-level governance without changing the copilot's business logic.

---

### Multi-Tenant SaaS — Per-Tenant Cost Tracking

A SaaS platform offers AI features across free, pro, and enterprise tiers. Today, all AI usage runs through a single OpenAI key per environment — making it impossible to answer "how much did Org X spend?" or "which users hit quota?"

**Before Gatewaystack:** One big shared key. No tenant-level attribution. Cost overruns are invisible until the bill arrives.

**With Gatewaystack:**
- `identifiabl` attaches `user_id` and `org_id` to every request
- `validatabl` enforces tier-based feature access (`plan:free`, `plan:pro`, `feature:advanced-rag`)
- `limitabl` enforces per-tenant quotas and budgets
- `explicabl` produces per-tenant usage reports

**Result:** Per-tenant accountability without changing app logic.

---

## What's Different from Traditional API Gateways?

**Identity Providers (Auth0, Okta, Cognito, Entra ID)**  
Handle login and token minting, but stop at the edge of your app. They don't understand model calls, tools, or which provider a request is going to — and they don't enforce user identity inside the AI gateway.

**API Gateways and Service Meshes (Kong, Apigee, AWS API Gateway, Istio, Envoy)**  
Great at path/method-level auth and rate limiting, but they treat LLMs like any other HTTP backend. **You can build AI governance on top of them** (Kong plugins, Istio policies, Lambda authorizers), **but it requires 100+ hours of custom development** to replicate what Gatewaystack provides out-of-the-box: user-scoped identity normalization, per-tool scope enforcement, pre-flight cost checks, Apps SDK / MCP compliance, and AI-specific audit trails.

**Cloud AI Gateways (Cloudflare AI Gateway, Azure OpenAI + API Management, Vertex AI, Bedrock Guardrails)**  
Focus on provider routing, quota, and safety filters at the tenant or API key level. User identity is usually out-of-band or left to the application.

**Hand-Rolled Middleware**  
Many teams glue together JWT validation, headers, and logging inside their app or a thin Node/Go proxy. It works... until you need to support multiple agents, providers, tenants, and audit/regulatory requirements.

**Gatewaystack is different:**
- **User-scoped by default** — every request is tied to a verified user, not a shared key
- **Model-aware** — understands tools, scopes, and provider semantics (Apps SDK, MCP, OpenAI, Anthropic)
- **Composable governance** — each layer (identity, policy, limits, routing, audit) can run standalone or as part of the full control plane
- **Built for agents** — prevents runaway loops, enforces per-workflow budgets, and tracks multi-step traces

**Example: Kong + OpenAI**

To get user-scoped AI governance with Kong, you'd need to:
1. Install `jwt` plugin (validate tokens)
2. Install `request-transformer` plugin (inject headers)
3. Write custom Lua script to normalize identity claims
4. Write custom Lua script for scope-to-tool mapping
5. Write custom plugin for pre-flight cost estimation
6. Build separate service for Protected Resource Metadata
7. Configure DCR flow manually
8. Build custom audit log forwarding

**Estimate: 100-200 hours of development + ongoing maintenance.**

**With Gatewaystack:** Configure `.env` file, deploy, done. (2 hours)

You can still run Gatewaystack alongside traditional API gateways — it's the **user-scoped identity and governance slice** of your AI stack.

---

### GatewayStack vs Traditional API Gateways

| Feature | Kong/Apigee/AWS API Gateway | Gatewaystack |
|---------|---------------------------|--------------|
| **JWT validation** | ✅ Built-in | ✅ Built-in |
| **Rate limiting** | ✅ Built-in | ✅ Built-in |
| **Path/method routing** | ✅ Built-in | ✅ Built-in |
| **User identity normalization** | ❌ Manual (custom plugin) | ✅ Built-in |
| **Per-tool scope enforcement** | ❌ Manual (custom policy) | ✅ Built-in |
| **Apps SDK / MCP compliance** | ❌ Manual (PRM endpoint) | ✅ Built-in |
| **Pre-flight cost checks** | ❌ Manual (custom plugin) | ✅ Roadmap |
| **Model-specific policies** | ❌ Manual (custom logic) | ✅ Built-in |
| **AI audit trails** | ❌ Manual (log forwarding) | ✅ Built-in |
| **Setup time** | 100+ hours (custom dev) | 2 hours (config) |

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

### Demo mode env

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

## Getting Started

Choose your path:

**Quickstart (10 min)** → Run local demos without Auth0  
**Production Setup (30 min)** → Connect to Auth0/Okta + ChatGPT/Claude  
**Deployment** → Cloud Run, Docker, Kubernetes


## Quickstart (10 minutes)

```bash
git clone <your-repo-url> gatewaystack
cd gatewaystack
npm install
npm run dev
```

### What You Get

- ✅ **RS256 JWT Verification** via JWKS (issuer, audience, exp, nbf, sub checks)
- ✅ **Per-tool scope enforcement** (deny-by-default; 401/403 outcomes)
- ✅ **Protected resource endpoint** for smoke tests
- ✅ **Verified Identity Injection** — The gateway injects a cryptographically verified user ID (`X-User-Id`) into every proxied request, so downstream services can enforce per-user/per-tenant filtering without ever handling JWTs or seeing upstream API keys. This turns "shared key chaos" into "every call is attributable."
- ✅ **Rate limiting** (user/tenant aware)
- ✅ **Health endpoints** (`/health`, `/health/auth0`)
- ✅ *(Optional)* **DCR webhook** to auto-promote new OAuth clients from Auth0 logs
- ✅ **Echo test servers** to validate proxy/header injection

### Prerequisites

- Node.js **20+** (or 22)
- npm **10+** (or pnpm 9)
- An **Auth0 tenant** (or equivalent OIDC provider issuing RS256 access tokens)
- *(Optional)* Google Cloud SDK for Cloud Run deploys

### Minimal Auth0 Setup (≈10 minutes)

> **🔓 Works with Any Identity Provider**  
> Gatewaystack is IdP-agnostic. It works with any OAuth 2.1 / OIDC provider that issues RS256 JWTs: Auth0, Okta, Entra ID (Azure AD), Keycloak, Google OAuth, or custom implementations.  
> Auth0 examples are provided for quick setup—the same patterns apply to all providers. See [Identity Provider Requirements](#identity-provider-requirements) for details.

**Requirements for any IdP:** See [Identity Provider Requirements](#identity-provider-requirements) below.

### Identity Provider Requirements

Gatewaystack requires an OAuth 2.1 / OIDC provider that issues **RS256 JWTs**.

#### What Your IdP Must Support

| Requirement | Why | Example Providers |
|-------------|-----|-------------------|
| **RS256 JWT signing** | Gateway validates signatures via JWKS | Auth0, Okta, Entra ID, Keycloak |
| **Public JWKS endpoint** | Gateway fetches public keys at runtime | `https://tenant.auth0.com/.well-known/jwks.json` |
| **Standard claims** | Gateway reads: `iss`, `aud`, `sub`, `exp`, `nbf` | All OAuth 2.1 providers |
| **Custom scopes** | For authorization (`tool:read`, `tool:write`) | Configure in your IdP's API settings |
| **OAuth 2.1 + PKCE** | Required for ChatGPT Apps SDK / MCP flows | Auth0, Okta, Entra ID |

---

#### Supported Providers

| Provider | Status | Notes |
|----------|--------|-------|
| **Auth0** | ✅ Fully tested | See [setup guide](#minimal-auth0-setup-10-minutes) above |
| **Okta** | ✅ Compatible | Coming soon: `docs/okta-setup.md` |
| **Entra ID** | ✅ Compatible | Coming soon: `docs/entra-id-setup.md` |
| **Keycloak** | ✅ Compatible | Community guide available |
| **Google OAuth** | ✅ Compatible | Standard RS256 setup |
| **Custom** | ✅ Any RS256 provider | Must meet requirements above |

**Need help with your IdP?** Open a [GitHub Discussion](https://github.com/davidcrowe/gatewaystack/discussions).

---

#### Create an API (Auth0 Dashboard → Applications → APIs)

* **Name:** `Gateway API`
* **Identifier (Audience):** `https://gateway.local/api` *(any HTTPS URI string)*
* **Signing algorithm:** `RS256`
* Enable **RBAC** and **Add Permissions in the Access Token**

---

#### Define permissions/scopes (examples)

* `tool:read`
* `tool:write`

---

#### Create an Application

Create a **Regular Web App** or **SPA** to obtain tokens during development.

---

#### Well-Known Issuer

Your issuer will be:

```
https://<TENANT>.region.auth0.com/
```

---

#### (Optional) Management API client (for DCR webhook)

Create a **Machine-to-Machine** application with scopes:

```
read:clients update:clients read:connections update:connections read:logs
```

---

#### Get a dev access token

* From your app’s Auth0 **Test** tab or via a quick PKCE flow.
* Ensure the token’s **audience** matches your API identifier and includes the scopes you want to test (e.g., `tool:read`).

---
### Auth0 Post-Login Action for ChatGPT connectors
> **⚠️ Auth0-Specific Feature**  
> This section only applies if you're using Auth0 + ChatGPT Apps SDK.  
> Okta and Entra ID have equivalent mechanisms (Hooks, Custom Extensions).

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

## Environment Variables

Core OAuth config uses the `OAUTH_*` prefix:
- `OAUTH_ISSUER`, `OAUTH_AUDIENCE`, `OAUTH_JWKS_URI`, `OAUTH_ENFORCE_ALG`

Auth0-specific features use `AUTH0_*`:
- `AUTH0_DOMAIN`, `AUTH0_MGMT_CLIENT_ID`, `AUTH0_MGMT_CLIENT_SECRET` (for DCR webhook and `/health/auth0`)

Demo mode uses `OAUTH_*_DEMO` variants:
- `OAUTH_ISSUER_DEMO`, `OAUTH_AUDIENCE_DEMO`, etc.

See `apps/gateway-server/.env.example` for the full reference, including:
- Rate limiting (`RATE_LIMIT_*`)
- Proxy config (`PROXY_TARGET`, `PROXY_INJECT_*`)
- Tool scopes (`TOOL_SCOPES_JSON`)
- DCR webhook (`MGMT_*`, `LOG_WEBHOOK_SECRET`)

---

### Start the Test Backends (Echo Servers)

These help prove proxy + header injection:

```bash
# Echo server that returns headers, query, and body
npm run -w @gatewaystack/echo-server dev
# default: http://localhost:3333
```

These tests are your **governance smoke test**.

The echo server simply returns the headers, query, and body it receives. Combined with the `/proxy` routes in `proxyabl`, this lets you prove that the authenticated subject has been injected as a **verified, canonical user identifier** (for example `X-User-Id`) — so downstream services can enforce per-user/per-tenant data filtering without ever seeing upstream API keys.

Need a fake tool backend instead of an echo? Run `tsx tools/mock-tools-server/index.ts` to spin up JSON handlers (on :9090 by default) that mimic `generateDreamSummary`, `chatWithEmbeddingsv3`, etc. for end-to-end proxy tests.

---

### Run the Gateway (dev)

From the repo root:

```bash
# Or individually:
npm run dev:server   # apps/gateway-server
npm run dev:admin    # apps/admin-ui
```

- `npm run dev` starts the gateway and Admin UI together.
- `npm run dev:server` starts the Express gateway only.
- `npm run dev:admin` starts the Admin UI, which is primarily used to visualize `/health` and related outputs.

---

### Health & Basic Smoke Tests

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

* `/health` → `{ ok: true, ... }`
* `/health/auth0` → issuer/audience OK, JWKS reachable
* Protected resource → **401** w/o token, **200** w/ token

## Testing

Run the full test suite:
```bash
npm test
```

This runs Vitest plus the conformance report writer that updates `docs/conformance.json`.

For detailed testing workflows, see:
- `docs/testing.md` — `/__test__/echo` routes, scope checks, proxy validation
- `CONTRIBUTING.md` — Pre-PR checklist

### DCR Webhook (Optional)

The DCR helper is implemented inside the **Explicabl** router and exposed at:

```http
POST /webhooks/auth0/logs
```

> **When to use this:** If you want new ChatGPT connectors to **auto-register** in Auth0 and immediately gain access to your API with the correct grant types, Google connection, and scopes, enable the DCR webhook.

This endpoint is typically wired as an Auth0 **Log Stream** target that listens for `/oidc/register` events (Dynamic Client Registration) and then:

- Promotes the new client to a public `regular_web` app with PKCE.
- Enables the `google-oauth2` connection for that client.
- Ensures a client grant exists for your API (`OAUTH_AUDIENCE`) with all `REQUIRED_SCOPES`.

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

### Troubleshooting

> **Using Auth0 + ChatGPT?** For Auth0-specific issues (Post-Login Actions, JWE vs JWS tokens, scopes not showing up, etc.), see `docs/auth0/chatgpt-post-login-action.md` → “Troubleshooting checklist”.

**401 with valid token**

* Check `OAUTH_AUDIENCE` matches the token `aud`
* Check `OAUTH_ISSUER` matches token `iss` and the JWKS URL resolves
* Ensure **RS256** is used; HS256 will be rejected when `OAUTH_ENFORCE_ALG=RS256`

**403 on write**

* Your token likely lacks `tool:write`; confirm “Add Permissions in the Access Token” is enabled on the API

**Proxy not injecting user**

* Verify `PROXY_TARGET` is reachable
* Confirm `PROXY_INJECT_HEADER` / `PROXY_INJECT_QUERY` are set and your route is going through the proxy handler

**Rate limit never triggers**

* Lower `RATE_LIMIT_MAX` and ensure identifier (user/tenant) is parsed from the token’s `sub` / `org_id`

---

### Production Checklist

* ✅ RS256 enforced; JWKS timeout & caching tuned
* ✅ Strict CORS (exact origins)
* ✅ Deny-by-default policies per route/tool
* ✅ Rate-limit per user/tenant with sane ceilings
* ✅ Logs redact PII; audit fields: `{sub, tool, path, decision, latency}`
* ✅ Health probes hooked into your orchestrator
* ✅ *(Optional)* DCR webhook secret rotated; Mgmt API scopes minimal

## Deployment

### Cloud Run (Recommended for Quick Start)

**Why Cloud Run:**
- ✅ Serverless (no infrastructure management)
- ✅ Auto-scaling (0 to 1000+ instances)
- ✅ FedRAMP Moderate authorized (government/enterprise ready)
- ✅ Built-in HTTPS, load balancing, health checks
- ✅ Deploy in 3 commands

**Quick Deploy:**
```bash
# Use the included deploy script
./tools/deploy/cloud-run.sh apps/gateway-server

# Or manually:
gcloud builds submit --tag gcr.io/YOUR-PROJECT/gatewaystack
gcloud run deploy gatewaystack \
  --image gcr.io/YOUR-PROJECT/gatewaystack \
  --set-env-vars="OAUTH_ISSUER=https://your-tenant.auth0.com/"
```

**Cost:** ~$5-50/month depending on usage (generous free tier)

**See:** `docs/deployment/cloud-run.md` for full walkthrough

---

### Docker (Self-Hosted)

**Pre-built images:**
```bash
docker pull ghcr.io/davidcrowe/gatewaystack:latest
```

**Build yourself:**
```bash
# Gateway server
docker build -f apps/gateway-server/Dockerfile -t gatewaystack .

# Admin UI
docker build -f apps/admin-ui/Dockerfile -t gatewaystack-admin .
```

**Run locally:**
```bash
docker run -p 8080:8080 \
  -e OAUTH_ISSUER=https://your-tenant.auth0.com/ \
  -e OAUTH_AUDIENCE=https://gateway.local/api \
  gatewaystack
```

**See:** `docs/deployment/docker.md` for Docker Compose, Kubernetes manifests, etc.

---

### Other Platforms

| Platform | Difficulty | Guide |
|----------|------------|-------|
| **AWS ECS/Fargate** | Medium | `docs/deployment/aws.md` |
| **Azure Container Instances** | Medium | `docs/deployment/azure.md` |
| **Fly.io** | Easy | `docs/deployment/fly.md` |
| **Railway** | Easy | `docs/deployment/railway.md` |
| **Kubernetes** | Hard | `docs/deployment/kubernetes.md` |

**Air-gapped / on-prem deployments:** Fully supported (Docker + self-hosted)

---

### CI/CD

`.github/workflows/conformance.yml` runs `npm test` and updates `docs/conformance.json` on every push to main.

**To add deployment:**
```yaml
# Add to conformance.yml after tests pass
- name: Deploy to Cloud Run
  if: github.ref == 'refs/heads/main'
  run: ./tools/deploy/cloud-run.sh apps/gateway-server
  env:
    GCP_PROJECT: ${{ secrets.GCP_PROJECT }}
```

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

### ⚙️ Implementation Notes

* Always validate `iss`, **pin `aud`**, enforce `alg = RS256`, and honor `exp`/`nbf`.
* Keep tokens **short-lived**; rotate/revoke via your IdP.
* Use gateway **identity injection** (e.g. `X-User-Id`) to pass user context downstream — never expose upstream API keys to the LLM client.

## What's Next?

### For Developers
- 📖 Read the [Architecture Guide](docs/architecture.md)
- 🧪 Run the [conformance tests](docs/testing.md)
- 🔧 Explore the [API Reference](docs/api-reference.md)
- 💬 Ask questions in [GitHub Discussions](https://github.com/davidcrowe/gatewaystack/discussions)

### For Enterprises
- 🏢 Review the [Enterprise Features](docs/enterprise.md)
- 🔒 See [Compliance Documentation](docs/compliance.md) (SOC 2, HIPAA, FedRAMP)
- 📞 Contact us for [deployment support](https://reducibl.com)

### For Contributors
- 🤝 Read [CONTRIBUTING.md](CONTRIBUTING.md)
- 🐛 Report bugs via [GitHub Issues](https://github.com/davidcrowe/gatewaystack/issues)
- ⭐ Star the repo if this helps you!



Built by [reducibl applied AI studio](https://reducibl.com)