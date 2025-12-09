# GatewayStack 
## Agentic Control Plane for User-Scoped AI Governance

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)
![Cloud Run](https://img.shields.io/badge/Cloud%20Run-ready-4285F4)
![Auth0](https://img.shields.io/badge/Auth0-RS256-orange)
[![MCP/Auth Conformance](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fdavidcrowe%2Fgatewaystack%2Fmain%2Fdocs%2Fconformance.json&query=$.version&label=MCP%2FAuth%20Conformance)](https://github.com/davidcrowe/gatewaystack/tree/main/docs/conformance.json)

GatewayStack is an open-source Agentic Control Plane that makes AI agents **enterprise-ready** by enforcing user-scoped identity, policy, limits, and audit trails on every model call.

```bash
npm install @gatewaystack/identifiabl @gatewaystack/proxyabl @gatewaystack/explicabl @gatewaystack/request-context \
```

> **Early-stage:** GatewayStack is under active development  
> Three layers are live on npm — `@gatewaystack/identifiabl`, `@gatewaystack/proxyabl`, and `@gatewaystack/explicabl`  
> Three layers on the roadmap — `@gatewaystack/transformabl`, `@gatewaystack/validatabl`, and `@gatewaystack/limitabl`  

**The three-party problem:**  

Modern AI apps involve three actors — the **user**, the **LLM**, and **your backend** — yet there is no shared identity layer binding them together. This creates data leakage, policy bypass, and audit gaps.

- Users want AI to access *their* data (ChatGPT reading *my* calendar). 
- Enterprises want to control *who* can use AI models (only doctors can use medical models, only directors can send sensitive prompts). 

Both the LLM and your backend require **cryptographic proof of user identity** tied to every AI request... but AI platforms authenticate users on their side while your backend has no verified identity to enforce policies, filter data, or log actions. This is the [three-party problem](docs/three-party-problem.md).

**GatewayStack solves the three-party problem** by attaching a cryptographically verified user identity to every AI request and enforcing structured governance around it.

Drop GatewayStack between AI clients (ChatGPT, Claude, your own self-hosted models, MCP) and your backend. It validates OAuth tokens, enforces scopes, and injects verified identity—so you can safely answer the two questions that matter most:

1. **Who** did what, with **which** data, via **which** model?
2. Was it **authorized**, **bounded**, and **logged** under policy?

Every AI request flows through six governance checkpoints:
> **Identified → Transformed → Validated → Constrained → Routed → Audited**

**In short, GatewayStack lets you:**

- Verify **real user identity** on every AI request (RS256 JWTs via your IdP)
- Enforce **per-user / per-tenant** policies and scopes for tools and models
- Apply **rate limits & spend caps** per user/team/org
- Inject **X-User-Id / X-Org-Id** into downstream services (no JWT handling there)
- Emit **audit-ready logs** for “who did what, with which data, via which model”

→ See full examples: **[docs/examples.md](docs/examples.md)**

---

## Quickstart — Code (3 minutes)

Install the identity, routing, and audit layers:

```bash
npm install \
  @gatewaystack/identifiabl \
  @gatewaystack/proxyabl \
  @gatewaystack/explicabl \
  @gatewaystack/request-context \
  express

# (optional, if you don't have them yet)
npm install -D typescript ts-node
```

Create **app.ts**:

```ts
import express from "express";
import { runWithGatewayContext } from "@gatewaystack/request-context";
import { identifiabl } from "@gatewaystack/identifiabl";
import { createProxyablRouter, configFromEnv } from "@gatewaystack/proxyabl";
import { createConsoleLogger, explicablLoggingMiddleware } from "@gatewaystack/explicabl";

const app = express();

// 1. Establish request context for downstream layers
app.use((req, _res, next) => {
  runWithGatewayContext(
    { request: { method: req.method, path: req.path } },
    () => next()
  );
});

// 2. Log every request
app.use(explicablLoggingMiddleware(createConsoleLogger()));

// 3. Require verified RS256 token
app.use(identifiabl({
  issuer: process.env.OAUTH_ISSUER!,
  audience: process.env.OAUTH_AUDIENCE!,
  jwksUri: process.env.OAUTH_JWKS_URI
}));

// 4. Route /tools to your tool/model backends
app.use("/tools", createProxyablRouter(configFromEnv(process.env)));

app.listen(8080, () => {
  console.log("GatewayStack running on :8080");
});
```

Run it:

```bash
npx ts-node app.ts
# or:
# npx tsx app.ts
# or compile with tsc and run:
# npx tsc && node dist/app.js
```

## Quickstart — CLI

Clone the repo and run the reference gateway:

```bash
git clone https://github.com/davidcrowe/GatewayStack
cd GatewayStack
npm install
npm run dev
```

This starts:

- Gateway server on :8080
- Admin UI on :5173 (visualizes /health)

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

### Core Governance Layers

| Layer         | Status | Purpose |
|---------------|--------|---------|
| **identifiabl**  | ✅ | Trust & Identity Binding (verifies RS256 JWTs) |
| **transformabl** | ⚪ | Content safety preprocessing (redaction, normalization) |
| **validatabl**   | ⚪ | Authorization & scope-based policy enforcement |
| **limitabl**     | ⚪ | Rate & spend governance per user/tenant |
| **proxyabl**     | ✅ | Identity-aware routing for tools/models |
| **explicabl**    | ✅ | Audit-grade request logging & health endpoints |

---

### GatewayStack vs Traditional API Gateways

| Feature | Kong/Apigee/AWS API Gateway | GatewayStack |
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

## Docs

- [The Three-Party Problem](docs/three-party-problem.md)
- [Examples](docs/examples.md)
- [Demos](docs/demo.md)
- [Environment & health endpoints](docs/operations.md)
- [Deployment](docs/deployment.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Production checklist](docs/production-checklist.md)

## Testing

Run the full test suite:

```bash
npm test
```

This runs Vitest plus the conformance report writer that updates `docs/conformance.json`.

## Contributing

- Run the tests: `npm test`
- Read [`CONTRIBUTING.md`](CONTRIBUTING.md)
- Report issues on [GitHub Issues](https://github.com/davidcrowe/GatewayStack/issues)
- Star the repo if GatewayStack helps you


Built by [reducibl applied AI studio](https://reducibl.com)