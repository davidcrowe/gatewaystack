// packages/proxyabl-core/src/auth.ts
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";
import type { ProxyablConfig } from "./config.js";
import { trimTrailingSlashes } from "./config.js";

/**
 * Normalized, verified access token surface returned by core.
 * Express wrappers (proxyabl) can adapt this into HTTP response logic.
 */
export interface VerifiedAccessToken {
  sub: string;
  email?: string;
  effectiveScopes: string[];
  payload: JWTPayload;
}

/**
 * Core auth error type for proxyabl.
 * No HTTP semantics here beyond status code + code string.
 */
export class ProxyablAuthError extends Error {
  code: string;
  status: number;

  constructor(code: string, message: string, status = 401) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

interface VerifyAccessTokenOptions {
  debugAuth?: boolean;
  logger?: (msg: string, meta: Record<string, unknown>) => void;
}

/**
 * Verify an OAuth access token using OIDC/JWKS and return a normalized view.
 * - Validates issuer and audience (if configured)
 * - Extracts sub/email/scopes into a canonical structure
 */
export async function verifyAccessToken(
  config: ProxyablConfig,
  token: string,
  opts: VerifyAccessTokenOptions = {},
): Promise<VerifiedAccessToken> {
  const issuerRaw = config.oidc.issuer;
  const issuer = trimTrailingSlashes(issuerRaw);

  const jwksUri = config.oidc.jwksUri ?? `${issuer}/.well-known/jwks.json`;

  const JWKS = createRemoteJWKSet(new URL(jwksUri));
  const { debugAuth, logger } = opts;
  const log = logger ?? (() => {});

  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: [issuer, `${issuer}/`],
      ...(config.oidc.audience ? { audience: config.oidc.audience } : {}),
    });

    const sub = String(payload.sub || "");
    if (!sub) {
      throw new ProxyablAuthError("TOKEN_NO_SUB", "Token missing sub claim", 401);
    }

    const email =
      typeof (payload as any).email === "string"
        ? ((payload as any).email as string)
        : undefined;

    const scopeStr =
      typeof (payload as any).scope === "string"
        ? ((payload as any).scope as string)
        : "";
    const scopeList = scopeStr.split(" ").filter(Boolean);

    const permissions = Array.isArray((payload as any).permissions)
      ? ((payload as any).permissions as string[])
      : [];

    const effectiveScopes = Array.from(new Set([...scopeList, ...permissions]));

    if (debugAuth) {
      log("jwt_verified", {
        iss: payload.iss,
        aud: payload.aud,
        sub,
        scopeCount: effectiveScopes.length,
      });
    }

    return { sub, email, effectiveScopes, payload };
  } catch (err: any) {
    if (err instanceof ProxyablAuthError) {
      throw err;
    }

    const message = err?.message || "JWT verification failed";
    throw new ProxyablAuthError("JWT_VERIFY_FAILED", message, 401);
  }
}

/**
 * Return the scopes required for a given tool name, based on config.toolScopes.
 */
export function getRequiredScopesForTool(
  config: ProxyablConfig,
  toolName: string,
): string[] {
  const toolScopes = config.toolScopes ?? {};
  return toolScopes[toolName] ?? [];
}

/**
 * Assert that the caller's scopes satisfy the requirements for `toolName`.
 * Throws ProxyablAuthError(INSUFFICIENT_SCOPE) if not satisfied.
 */
export function assertToolScopes(
  config: ProxyablConfig,
  toolName: string,
  have: string[],
): void {
  const need = getRequiredScopesForTool(config, toolName);
  if (!need.length) return;

  const ok = need.every((s) => have.includes(s));
  if (!ok) {
    throw new ProxyablAuthError(
      "INSUFFICIENT_SCOPE",
      `Caller lacks required scopes for tool ${toolName}`,
      403,
    );
  }
}
