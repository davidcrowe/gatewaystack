// packages/proxyabl-core/src/oidc.ts
import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload,
  type JWTVerifyGetKey,
} from "jose";
import type { ProxyablConfig } from "./config";

export interface VerifiedAccessTokenPayload extends JWTPayload {
  sub?: string;
  scope?: string;
  permissions?: string[]; // Auth0-style permissions array
  [key: string]: unknown;
}

export interface VerifiedAccessToken {
  payload: VerifiedAccessTokenPayload;
}

// Simple in-memory cache keyed by issuer (no trailing slash)
type IssuerKey = string;
const jwksCache = new Map<IssuerKey, JWTVerifyGetKey>();

function normalizeIssuer(issuer: string): string {
  return issuer.replace(/\/+$/, "");
}

function getIssuerVariants(issuerRaw: string): string[] {
  const base = normalizeIssuer(issuerRaw);
  return [base, `${base}/`];
}

function getJwksForConfig(config: ProxyablConfig): JWTVerifyGetKey {
  const issuerKey = normalizeIssuer(config.oidc.issuer);

  const existing = jwksCache.get(issuerKey);
  if (existing) return existing;

  const jwksUri =
    config.oidc.jwksUri ??
    `${normalizeIssuer(config.oidc.issuer)}/.well-known/jwks.json`;

  const remote = createRemoteJWKSet(new URL(jwksUri));
  jwksCache.set(issuerKey, remote);
  return remote;
}

/**
 * Verify a raw access token using the ProxyablConfig OIDC settings.
 * - Validates issuer (with/without trailing slash)
 * - Validates audience if configured
 */
export async function verifyAccessToken(
  token: string,
  config: ProxyablConfig
): Promise<VerifiedAccessToken> {
  const jwks = getJwksForConfig(config);
  const issuers = getIssuerVariants(config.oidc.issuer);

  const verifyOpts: Parameters<typeof jwtVerify>[2] = {
    issuer: issuers,
  };

  if (config.oidc.audience) {
    (verifyOpts as any).audience = config.oidc.audience;
  }

  const { payload } = await jwtVerify(token, jwks, verifyOpts);
  return { payload: payload as VerifiedAccessTokenPayload };
}

/**
 * Extract a string subject ("sub") from a verified payload.
 * Empty string if missing.
 */
export function extractSub(payload: VerifiedAccessTokenPayload): string {
  return typeof payload.sub === "string" ? payload.sub : "";
}

/**
 * Merge scopes from:
 * - space-delimited "scope" claim
 * - Auth0 "permissions" string[]
 */
export function extractScopes(
  payload: VerifiedAccessTokenPayload
): string[] {
  const scopeStr =
    typeof payload.scope === "string" ? payload.scope : "";
  const scopeList = scopeStr.split(" ").filter(Boolean);

  const permissions = Array.isArray((payload as any).permissions)
    ? ((payload as any).permissions as string[])
    : [];

  return Array.from(new Set([...scopeList, ...permissions]));
}
