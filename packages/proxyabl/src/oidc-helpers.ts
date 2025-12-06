// packages/proxyabl/src/oidc-helpers.ts
import type { Request } from "express";
import type { ProxyablConfig } from "../../proxyabl-core/src/config";

/**
 * Normalize issuer: no trailing slash.
 */
export function getIssuer(config: ProxyablConfig): string {
  return config.oidc.issuer.replace(/\/+$/, "");
}

export function getAudience(config: ProxyablConfig): string | undefined {
  return config.oidc.audience;
}

export function getJwksUri(config: ProxyablConfig): string {
  const issuer = getIssuer(config);
  return config.oidc.jwksUri ?? `${issuer}/.well-known/jwks.json`;
}

/**
 * Scopes that clients should request.
 * We add some base OIDC scopes on top of required tool scopes.
 */
export function getScopesSupported(config: ProxyablConfig): string[] {
  const base = ["openid", "email", "profile"];
  const required = getRequiredScopes(config);
  return Array.from(new Set([...base, ...required]));
}

/**
 * Union of all required scopes across tools.
 */
export function getRequiredScopes(config: ProxyablConfig): string[] {
  const toolScopes = config.toolScopes || {};
  const all: string[] = [];

  for (const scopes of Object.values(toolScopes)) {
    if (Array.isArray(scopes)) {
      for (const s of scopes) {
        if (typeof s === "string" && s.trim().length > 0) {
          all.push(s);
        }
      }
    }
  }

  return Array.from(new Set(all));
}

/**
 * RFC 9728-style WWW-Authenticate header for this resource server.
 */
export function buildWwwAuthenticate(
  config: ProxyablConfig,
  req: Request
): string {
  const xfProto = req.get("x-forwarded-proto") || req.protocol || "https";
  const xfHost = req.get("x-forwarded-host") || req.get("host") || "";
  const base = `${xfProto}://${xfHost}`;
  const metaUrl = `${base}/.well-known/oauth-protected-resource`;

  const scopes = getScopesSupported(config).join(" ");
  const audience = getAudience(config);
  const resourceParam = audience ? `, resource="${audience}"` : "";

  // RFC 9728: use resource_metadata
  return `Bearer resource_metadata="${metaUrl}", scope="${scopes}"${resourceParam}`;
}

// --- Small robust fetch with timeout + retry (ported from toolGatewayHandler) ---

export async function fetchJsonWithRetry(
  url: string,
  tries = 3,
  timeoutMs = 4000
): Promise<any> {
  let lastErr: unknown;
  for (let i = 0; i < tries; i++) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const r = await fetch(url, {
        headers: { accept: "application/json" },
        signal: ctrl.signal,
      } as any);
      clearTimeout(t);
      if (!r.ok) throw new Error(`http_${r.status}`);
      return await r.json();
    } catch (e) {
      lastErr = e;
      await new Promise((res) => setTimeout(res, 150 * (i + 1)));
    } finally {
      clearTimeout(t);
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error(String(lastErr));
}