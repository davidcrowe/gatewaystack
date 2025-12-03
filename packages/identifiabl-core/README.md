# @gatewaystack/identifiabl-core

> **Experimental** – core identity verification helper used by GatewayStack.  
> Verifies RS256 JWTs against a JWKS endpoint and maps them into a normalized `GatewayIdentity` object.

`@gatewaystack/identifiabl-core` is a small, framework-agnostic helper for:

- Verifying RS256 JWTs with `jose` and a remote JWKS URL
- Enforcing `iss` (issuer) and `aud` (audience)
- Normalizing identity claims (`sub`, `email`, `name`, tenant, roles, scopes, plan)
- Returning a consistent `VerifyResult` you can plug into Gateways, middlewares, or Firebase Functions

---

## Installation

```bash
npm install @gatewaystack/identifiabl-core jose
# or
yarn add @gatewaystack/identifiabl-core jose
# or
pnpm add @gatewaystack/identifiabl-core jose
```

## Quick Start

```typescript
import { createIdentifiablVerifier } from "@gatewaystack/identifiabl-core";

const verify = createIdentifiablVerifier({
  issuer: "https://dev-xxxxx.us.auth0.com/",
  audience: "https://inner.app/api",
  // optional mappings:
  source: "auth0",
  tenantClaim: "https://inner.app/tenant_id",
  roleClaim: "https://inner.app/roles",
  scopeClaim: "scope",
  planClaim: "https://inner.app/plan"
});

async function handleRequest(bearerToken: string) {
  const token = bearerToken.replace(/^Bearer\s+/i, "");

  const result = await verify(token);

  if (!result.ok) {
    console.error("JWT verification failed:", result.error, result.detail);
    // return 401 / throw / etc.
    return;
  }

  const { identity, payload } = result;

  console.log("Verified user:", identity.sub);
  console.log("Tenant:", identity.tenantId);
  console.log("Roles:", identity.roles);
  console.log("Scopes:", identity.scopes);
}
```

## API

### createIdentifiablVerifier(config)

```typescript
import { createIdentifiablVerifier } from "@gatewaystack/identifiabl-core";

const verify = createIdentifiablVerifier(config);
const result = await verify(token);
```

### IdentifiablCoreConfig

```typescript
interface IdentifiablCoreConfig {
  issuer: string;        // Expected issuer (e.g. Auth0 domain)
  audience: string;      // Expected audience / API identifier
  jwksUri?: string;      // Optional override; defaults to `${issuer}/.well-known/jwks.json`
  source?: string;       // Optional identity source label (e.g. "auth0", "stytch", "cognito")

  tenantClaim?: string;  // Claim name for tenant / org id
  roleClaim?: string;    // Claim name for roles array
  scopeClaim?: string;   // Claim name for space-separated scopes string
  planClaim?: string;    // Claim name for plan / subscription tier
}
```

#### issuer

Used both to:

- Build a default JWKS URL (`${issuer}/.well-known/jwks.json` after trimming trailing `/`)
- Validate the `iss` claim. Trailing slashes are tolerated (e.g. `https://foo/` equals `https://foo`).

#### audience

Passed directly to `jwtVerify` to enforce the `aud` claim.

#### jwksUri (optional)

Override if your JWKS lives somewhere else.

#### Claim mapping fields

Let you adapt to different identity providers without changing code:

- `tenantClaim` → mapped to `identity.tenantId`
- `roleClaim` → mapped to `identity.roles: string[]`
- `scopeClaim` → split on spaces into `identity.scopes: string[]`
- `planClaim` → mapped to `identity.plan`

### VerifyResult

```typescript
type VerifyResult =
  | {
      ok: true;
      identity: GatewayIdentity;
      payload: JWTPayload;
    }
  | {
      ok: false;
      error: string;
      detail?: string;
    };
```

#### On success

`identity` is a normalized view of the user:

- `sub`: subject (required)
- `issuer`: normalized issuer (no trailing `/`)
- `email`, `name` (if present)
- `tenantId`, `roles`, `scopes`, `plan` (based on your config)
- `source`: identity provider label (defaults to "auth0")
- `raw`: the full decoded JWT payload

#### On failure

- `error` is a short code (currently `invalid_token`)
- `detail` is the underlying error message from jose when available

## Example: Firebase Callable Function

```typescript
import * as functions from "firebase-functions/v2/https";
import { createIdentifiablVerifier } from "@gatewaystack/identifiabl-core";

const verify = createIdentifiablVerifier({
  issuer: "https://dev-xxxxx.us.auth0.com/",
  audience: "https://inner.app/api",
  tenantClaim: "https://inner.app/tenant_id"
});

export const myProtectedFunction = functions.onCall(async (req) => {
  const token = req.rawRequest.headers.authorization?.replace(/^Bearer\s+/i, "");
  if (!token) {
    throw new functions.HttpsError("unauthenticated", "Missing bearer token");
  }

  const result = await verify(token);
  if (!result.ok) {
    throw new functions.HttpsError("unauthenticated", "Invalid or expired token");
  }

  const { identity } = result;
  // Use identity.sub / identity.tenantId / etc.
  return { ok: true, user: identity.sub, tenantId: identity.tenantId };
});
```

## Implementation Notes

Uses `jose` under the hood:

- `createRemoteJWKSet` to fetch and cache keys
- `jwtVerify` with `algorithms: ["RS256"]`
- `clockTolerance: "60s"` to allow for small clock skew

Currently focused on RS256 JWTs; other algorithms are intentionally not allowed.

## Status

This package is pre-1.0 and may change as GatewayStack evolves. If you try it and run into issues, please open an issue or PR in the main GatewayStack repo.