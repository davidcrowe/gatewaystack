import type { RequestHandler } from "express";
import { createRemoteJWKSet, jwtVerify } from "jose";
import {
  updateGatewayContext,
  type GatewayIdentity,
} from "@gatewaystack/request-context";

export interface IdentifiablConfig {
  /**
   * Expected issuer, e.g. "https://example.auth0.com"
   * Can have or not have a trailing slash; we normalize it.
   */
  issuer: string;
  /**
   * Expected audience (API identifier).
   */
  audience: string;
  /**
   * Optional JWKS URI. If not provided, defaults to
   * `${issuerWithoutTrailingSlash}/.well-known/jwks.json`.
   */
  jwksUri?: string;
}

/**
 * Escape a string for safe use inside a RegExp literal.
 */
function escapeForRegex(input: string): string {
  return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Build a pattern that matches the issuer with or without a trailing slash.
 */
function buildIssuerPattern(issuer: string): RegExp {
  const issuerNoSlash = issuer.replace(/\/+$/, "");
  return new RegExp(`^${escapeForRegex(issuerNoSlash)}\\/?$`);
}

/**
 * Express middleware that:
 *  - Extracts a Bearer token
 *  - Verifies it with JWKS (jose)
 *  - Checks audience and issuer
 *  - Attaches the JWT payload to req.user
 */
import { createIdentifiablVerifier } from "identifiabl";

export function identifiabl(config: IdentifiablConfig): RequestHandler {
  const verify = createIdentifiablVerifier({
    ...config,
    scopeClaim: "scope",   // ⬅️ add this
  });

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

    // 🔹 result.identity is structurally compatible with GatewayIdentity
    const identity = result.identity as GatewayIdentity;

    // 🔹 publish identity into the shared GatewayContext
    updateGatewayContext({ identity });

    // Keep legacy behavior so existing code still works
    req.user = identity;

    return next();
  };

  return middleware;
}
