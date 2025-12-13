// packages/proxyabl/src/auth.ts
import type { Request } from "express";
import type { JWTPayload } from "jose";
import type { ProxyablConfig } from "@gatewaystack/proxyabl-core";

import {
  verifyAccessToken,
  assertToolScopes,
  getRequiredScopesForTool,
  ProxyablAuthError,
  type VerifiedAccessToken,
} from "@gatewaystack/proxyabl-core";

import {
  getGatewayContext,
  type GatewayIdentity,
} from "@gatewaystack/request-context";

import { buildWwwAuthenticate } from "./oidc-helpers.js";

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
  const { hasAuth } = readAuthHeader(req);

  const ctx = getGatewayContext();
  const identity = ctx?.identity as GatewayIdentity | undefined;

  if (!identity || !identity.sub) {
    // If there was a Bearer token but no identity, treat as invalid token.
    // If there was no Bearer, treat as missing auth.
    const code = hasAuth ? "INVALID_TOKEN" : "NO_AUTH";
    const message = hasAuth
      ? "Invalid or unverified access token"
      : "Missing Bearer token";

    const err = new ProxyablAuthError(code, message, 401) as ProxyablAuthError & {
      www?: string;
    };
    err.www = buildWwwAuthenticate(config, req) + ', error="invalid_token"';
    throw err;
  }

  const scopes = identity.scopes ?? [];
  const payload = identity.raw as JWTPayload;

  return {
    sub: identity.sub,
    email: identity.email,
    scopes,
    payload,
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
