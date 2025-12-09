# @gatewaystack/request-context

Lightweight request-scoped context for GatewayStack.

`@gatewaystack/request-context` gives you a single place to hang identity, policy, routing, and audit metadata for each incoming request — without threading it through every function call.

It’s intentionally tiny: underneath, it’s just an async-context helper (Node `AsyncLocalStorage` / equivalent) plus a shared `GatewayContext` shape that the other layers (`identifiabl`, `limitabl`, `proxyabl`, `explicabl`, etc.) can read/write.

---

## Install

```bash
npm install @gatewaystack/request-context
# or
pnpm add @gatewaystack/request-context
```

## Core concepts
- **`GatewayContext`** – a per-request object (e.g. { request, identity, authz, limits, routing }) that evolves as the request flows through the six layers.

- **`runWithGatewayContext`** – wraps a request lifecycle so downstream code can call getGatewayContext() and read/write state.

- **`getGatewayContext`** – reads the current context (or undefined if you’re outside a gateway scope).

The contract is:

- **Read-only** from the perspective of business handlers (they can inspect but shouldn’t mutate identity/policy arbitrarily).

- **Layer-owned** fields, e.g.:

-identity owned by identifiabl

-authz owned by validatabl

-limits owned by limitabl

-routing owned by proxyabl

-audit/eventIds observed by explicabl

## Quickstart
In your Express app:

```ts
import express from "express";
import { runWithGatewayContext } from "@gatewaystack/request-context";

const app = express();

app.use((req, _res, next) => {
  // Seed the context once per request
  runWithGatewayContext(
    {
      request: {
        method: req.method,
        path: req.path,
        ip: (req as any).ip,
        userAgent: req.get("user-agent") ?? undefined,
      },
    },
    () => next()
  );
});
```

Downstream, other packages can do:

```ts
import { getGatewayContext } from "@gatewaystack/request-context";

function someMiddleware(_req, _res, next) {
  const ctx = getGatewayContext();

  // e.g. identifiabl may attach canonical identity:
  // ctx.identity = { sub, orgId, scopes, ... };

  next();
}
```

## Usage with other GatewayStack layers
Typical flow:

1- runWithGatewayContext seeds ctx.request.

2- identifiabl verifies the JWT and writes ctx.identity.

3- validatabl reads ctx.identity and attaches ctx.authz (scopes, decisions).

4- limitabl reads ctx.identity and attaches ctx.limits (keys, decisions).

5- proxyabl reads ctx.identity / ctx.authz to route tools/models and inject headers.

6- explicabl reads the final context and emits an audit event.

You can also use it standalone in your own middleware, as long as you respect the “no breaking changes to existing fields” rule.