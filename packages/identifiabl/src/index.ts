import type { RequestHandler } from "express";
import { createRemoteJWKSet, jwtVerify } from "jose";

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
export function identifiabl(config: IdentifiablConfig): RequestHandler {
  const issuerNoSlash = config.issuer.replace(/\/+$/, "");
  const issuerPattern = buildIssuerPattern(config.issuer);
  const audience = config.audience;
  const jwksUri =
    config.jwksUri || `${issuerNoSlash}/.well-known/jwks.json`;

  const JWKS = createRemoteJWKSet(new URL(jwksUri));

  const middleware: RequestHandler = async (req: any, res, next) => {
    try {
      const auth = req.headers.authorization || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

      if (!token) {
        return res.status(401).json({ error: "missing_bearer" });
      }

      // Verify signature & audience
      const { payload } = await jwtVerify(token, JWKS, { audience });

      // Enforce expected issuer (with or without trailing slash)
      const iss = String(payload.iss || "");
      if (!issuerPattern.test(iss)) {
        return res.status(401).json({
          error: "invalid_token",
          detail: `unexpected "iss" claim value: ${iss}`,
        });
      }

      // Attach identity to the request
      req.user = payload;
      return next();
    } catch (e: any) {
      return res
        .status(401)
        .json({ error: "invalid_token", detail: e?.message });
    }
  };

  return middleware;
}
