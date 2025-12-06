// packages/proxyabl/src/auth.ts

import type { Request } from "express";
import type { JWTPayload } from "jose";
import type { ProxyablConfig } from "../../proxyabl-core/src/config";

import {
  verifyAccessToken,
  assertToolScopes,
  getRequiredScopesForTool,
  ProxyablAuthError,
  type VerifiedAccessToken,
} from "../../proxyabl-core/src/auth";

// AFTER
import {
  updateGatewayContext,
  type GatewayIdentity,
} from "@gatewaystack/request-context";


import { buildWwwAuthenticate } from "./oidc-helpers";

/**
 * Parsed Authorization header for quick diagnostics.
 */
export interface AuthHeaderShape {
  hasAuth: boolean;
  token: string;
  tokenShape: "jwt" | "opaque" | "none";
  len: number;
}

/**
 * Identity + scopes derived from a Request.
 */
export interface VerifiedRequestIdentity {
  sub: string;
  email?: string;
  scopes: string[];
  payload: JWTPayload;
}

/**
 * Cheap parser for the Authorization header.
 */
export function readAuthHeader(req: Request): AuthHeaderShape {
  const auth = req.header("authorization") || "";
  const hasAuth = auth.startsWith("Bearer ");
  const token = hasAuth ? auth.slice(7) : "";
  const tokenShape = token.includes(".")
    ? ("jwt" as const)
    : token
    ? ("opaque" as const)
    : ("none" as const);

  return { hasAuth, token, tokenShape, len: token.length };
}

/**
 * Verify a Bearer token from an Express Request using proxyabl-core's
 * verifyAccessToken. Throws ProxyablAuthError with .status/.code and
 * a `.www` property that can be used as WWW-Authenticate.
 *
 * ALSO: populates GatewayContext.identity so other layers can read it.
 */
export async function verifyBearerFromRequest(
  config: ProxyablConfig,
  req: Request,
): Promise<VerifiedRequestIdentity> {
  const { hasAuth, token, tokenShape } = readAuthHeader(req);

  if (!hasAuth) {
    const err = new ProxyablAuthError(
      "NO_AUTH",
      "Missing Bearer token",
      401,
    ) as ProxyablAuthError & { www?: string };
    err.www = buildWwwAuthenticate(config, req) + ', error="invalid_token"';
    throw err;
  }

  if (tokenShape !== "jwt") {
    const err = new ProxyablAuthError(
      "ACCESS_TOKEN_NOT_JWS",
      "Expecting JWT/JWS access token",
      401,
    ) as ProxyablAuthError & { www?: string };
    err.www =
      buildWwwAuthenticate(config, req) +
      ', error="invalid_token", error_description="Expecting JWS access token (3 parts)"';
    throw err;
  }

  const debugAuth = process.env.DEBUG_AUTH === "1";

  const verified: VerifiedAccessToken = await verifyAccessToken(
    config,
    token,
    {
      debugAuth,
      logger: (msg, meta) => {
        // Safe, state-only logging
        console.log(`[proxyabl.auth] ${msg}`, meta);
      },
    },
  );

  // 🔗 Bridge into GatewayContext.identity
  // For now, assume Auth0 as the source; later we can make this configurable.
  try {
    const identity: GatewayIdentity = {
      sub: verified.sub,
      issuer: config.oidc.issuer.replace(/\/+$/, ""),
      email: verified.email,
      scopes: verified.effectiveScopes,
      source: "auth0",
      raw: verified.payload as Record<string, unknown>,
    };

    updateGatewayContext({ identity });
  } catch (e) {
    console.warn("[proxyabl.auth] failed to update GatewayContext", {
      message: (e as Error)?.message,
    });
  }


  return {
    sub: verified.sub,
    email: verified.email,
    scopes: verified.effectiveScopes,
    payload: verified.payload,
  };
}

/**
 * Convenience helper: ensure the caller has the scopes required for `toolName`.
 * Throws ProxyablAuthError(INSUFFICIENT_SCOPE) on failure.
 */
export function ensureToolScopesForRequest(
  config: ProxyablConfig,
  toolName: string,
  scopes: string[],
): void {
  // This just delegates to core's assertToolScopes, but keeps
  // the wrapper name expressive in the router.
  assertToolScopes(config, toolName, scopes);
}

/**
 * Retrieve the required scopes for a tool (if any) – useful for
 * building MCP tool metadata, documentation, etc.
 */
export function getRequiredScopesForToolForConfig(
  config: ProxyablConfig,
  toolName: string,
): string[] {
  return getRequiredScopesForTool(config, toolName);
}
