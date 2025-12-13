// packages/identifiabl/src/index.ts
import type { RequestHandler } from "express";
import {
  updateGatewayContext,
  type GatewayIdentity,
} from "@gatewaystack/request-context";
import {
  createIdentifiablVerifier as coreCreateIdentifiablVerifier,
  // (optional) re-export types from core if you want
  // type IdentifiablResult,
} from "identifiabl";

export interface IdentifiablConfig {
  issuer: string;
  audience: string;
  jwksUri?: string;

  // Optional overrides, but we set good defaults for GatewayStack:
  source?: string;
  scopeClaim?: string;
  roleClaim?: string;
  tenantClaim?: string;
  planClaim?: string;
}

/**
 * Gateway-flavored identifiabl verifier.
 *
 * Wraps the core verifier and bakes in our standard conventions:
 * - source: "auth0"
 * - scopeClaim: "scope"
 * - roleClaim: "permissions"
 *
 * Call this in non-Express contexts (e.g., Cloud Run handlers) to get
 * a verifier that returns an identity usable as a GatewayIdentity.
 */
export function createIdentifiablVerifier(config: IdentifiablConfig) {
  return coreCreateIdentifiablVerifier({
    // 👇 GatewayStack defaults
    source: "auth0",
    scopeClaim: "scope",
    roleClaim: "permissions",
    // allow callers to override if needed
    ...config,
  });
}

/**
 * Express middleware:
 * - Reads Bearer token from Authorization header
 * - Verifies it with identifiabl
 * - Stores identity in GatewayContext and req.user
 */
export function identifiabl(config: IdentifiablConfig): RequestHandler {
  const verify = createIdentifiablVerifier(config);

  const middleware: RequestHandler = async (req: any, res, next) => {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

    if (!token) {
      return res.status(401).json({ error: "missing_bearer" });
    }

    const result = await verify(token);
    if (!result.ok) {
      return res.status(401).json(result);
    }

    const identity = result.identity as GatewayIdentity;
    updateGatewayContext({ identity });
    req.user = identity;

    return next();
  };

  return middleware;
}

// If you want to keep the old export shape exactly, this is now redundant but harmless:
// export const createIdentifiablVerifier = coreCreateIdentifiablVerifier;
