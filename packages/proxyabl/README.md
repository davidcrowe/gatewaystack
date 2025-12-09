## `packages/proxyabl/README.md`

```md
# @gatewaystack/proxyabl
```

**Execution control & identity-aware routing for tools and models.**

`@gatewaystack/proxyabl` is the layer that turns your gateway into a **tool / MCP / Apps SDK** hub:

- Serves PRM / OIDC metadata required by MCP & OAuth 2.1.
- Enforces **scope-to-tool** mappings (`TOOL_SCOPES_JSON`).
- Proxies JSON-RPC/tool calls to downstream services.
- Injects **verified identity** into headers/query for your backends.

This is where “who can call which tool/model” becomes an actual routing decision.

---

## Install

```bash
npm install @gatewaystack/proxyabl
# or
pnpm add @gatewaystack/proxyabl
```

## API
`configFromEnv(env)`
Reads environment variables into a typed config object used by the router.

```ts
interface ProxyablConfig {
  // Roughly:
  // - upstream base URLs, per tool/model
  // - PRM metadata (issuer, audience, token endpoint)
  // - tool scope mappings
  // - header injection rules, etc.
}

declare function configFromEnv(
  env: NodeJS.ProcessEnv
): ProxyablConfig;
Expected envs (high-level):
```

- TOOL_SCOPE_ALLOWLIST_JSON / TOOL_SCOPES_JSON – tool → scopes mapping.

- Upstream URLs for tools/models (e.g. TOOL_FOO_BASE_URL).

- OAuth / OIDC metadata for PRM endpoints.

`createProxyablRouter(config)`
Creates an Express router that wires:

- PRM/OIDC well-known endpoints.

- Tool/middleware entrypoints (e.g. /tools/*, /proxy).

- Auth0 integration endpoints (e.g. DCR, log streaming) where relevant.

```ts
import type { RequestHandler } from "express";

declare function createProxyablRouter(
  config: ProxyablConfig
): RequestHandler;
```

## Example
From the reference gateway server:

```ts
import rateLimit from "express-rate-limit";
import {
  createProxyablRouter,
  configFromEnv as proxyablConfigFromEnv,
} from "@gatewaystack/proxyabl";
import { identifiabl } from "@gatewaystack/identifiabl";

const identifiablMiddleware = identifiabl({ /* ... */ });
const proxyablConfig = proxyablConfigFromEnv(process.env);

// Slightly more generous limiter for /tools
const toolsRateLimiter = rateLimit({
  windowMs: +(process.env.RATE_LIMIT_WINDOW_MS ?? 60_000),
  max: +(process.env.RATE_LIMIT_MAX ?? 10) * 10,
  standardHeaders: true,
  legacyHeaders: false,
});

// /tools pipeline:
//   RequestContext (mounted globally)
//   → toolsRateLimiter
//   → identifiabl (JWT → ctx.identity)
//   → proxyabl router (scopes + routing)
app.use(
  "/tools",
  toolsRateLimiter,
  identifiablMiddleware,
  createProxyablRouter(proxyablConfig) as unknown as RequestHandler
);
```

Downstream services can then rely on headers like:

- `X-User-Id`

- `X-Org-Id`

- `X-User-Scopes`

to implement domain-specific policy without ever touching JWTs directly.