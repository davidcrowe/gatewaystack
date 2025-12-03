import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload,
} from "jose";

// import type {
//   GatewayIdentity,
//   IdentitySource,
// } from "@gatewaystack/request-context";

// remove this:
// import type { GatewayIdentity, IdentitySource } from "@gatewaystack/request-context";

export type IdentitySource =
  | "auth0"
  | "stytch"
  | "cognito"
  | "custom"
  | string;

export interface GatewayIdentity {
  sub: string;
  issuer: string;
  tenantId?: string;
  email?: string;
  name?: string;
  roles?: string[];
  scopes?: string[];
  plan?: string;
  source: IdentitySource;
  raw: Record<string, unknown>;
}

export interface IdentifiablCoreConfig {
  issuer: string;
  audience: string;
  jwksUri?: string;
  source?: IdentitySource;
  tenantClaim?: string;
  roleClaim?: string;
  scopeClaim?: string;
  planClaim?: string;
}

export interface VerifySuccess {
  ok: true;
  identity: GatewayIdentity;
  payload: JWTPayload;
}

export interface VerifyFailure {
  ok: false;
  error: string;
  detail?: string;
}

export type VerifyResult = VerifySuccess | VerifyFailure;

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

function mapPayloadToGatewayIdentity(
  payload: JWTPayload,
  config: IdentifiablCoreConfig,
  normalizedIssuer: string
): GatewayIdentity {
  const sub = typeof payload.sub === "string" ? payload.sub : "";
  if (!sub) {
    throw new Error('missing "sub" claim in token');
  }

  const email =
    typeof payload.email === "string" ? (payload.email as string) : undefined;
  const name =
    typeof payload.name === "string" ? (payload.name as string) : undefined;

  let tenantId: string | undefined;
  if (config.tenantClaim) {
    const rawTenant = payload[config.tenantClaim];
    if (typeof rawTenant === "string") {
      tenantId = rawTenant;
    }
  }

  let roles: string[] | undefined;
  if (config.roleClaim) {
    const rawRoles = payload[config.roleClaim];
    if (Array.isArray(rawRoles)) {
      roles = rawRoles.filter((r): r is string => typeof r === "string");
    }
  }

  let scopes: string[] | undefined;
  if (config.scopeClaim) {
    const rawScope = payload[config.scopeClaim];
    if (typeof rawScope === "string") {
      scopes = rawScope.split(" ").filter(Boolean);
    }
  }

  let plan: string | undefined;
  if (config.planClaim) {
    const rawPlan = payload[config.planClaim];
    if (typeof rawPlan === "string") {
      plan = rawPlan;
    }
  }

  return {
    sub,
    issuer: normalizedIssuer,
    tenantId,
    email,
    name,
    roles,
    scopes,
    plan,
    source: config.source ?? "auth0",
    raw: payload as Record<string, unknown>,
  };
}

/**
 * Factory that returns a token verifier you can use in any environment.
 */
export function createIdentifiablVerifier(
  config: IdentifiablCoreConfig
): (token: string) => Promise<VerifyResult> {
  const issuerNoSlash = config.issuer.replace(/\/+$/, "");
  const issuerPattern = buildIssuerPattern(config.issuer);
  const audience = config.audience;
  const jwksUri =
    config.jwksUri || `${issuerNoSlash}/.well-known/jwks.json`;

  const JWKS = createRemoteJWKSet(new URL(jwksUri));

  return async (token: string): Promise<VerifyResult> => {
    try {
      const { payload } = await jwtVerify(token, JWKS, {
        audience,
        algorithms: ["RS256"],
        clockTolerance: "60s"
      });

      const iss = String(payload.iss || "");
      if (!issuerPattern.test(iss)) {
        return {
          ok: false,
          error: "invalid_token",
          detail: `unexpected "iss" claim value: ${iss}`,
        };
      }

      const identity = mapPayloadToGatewayIdentity(
        payload,
        config,
        issuerNoSlash
      );

      return {
        ok: true,
        identity,
        payload,
      };
    } catch (e: any) {
      return {
        ok: false,
        error: "invalid_token",
        detail: e?.message,
      };
    }
  };
}