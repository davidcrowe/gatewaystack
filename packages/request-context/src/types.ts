// packages/request-context/src/types.ts

/**
 * Where the identity came from. Keep this open-ended so you
 * can add "entra", "okta", etc. without changing the lib.
 */
export type IdentitySource =
  | "auth0"
  | "demo"
  | "cognito"
  | "okta"
  | "entra"
  | "custom"
  | string;

/**
 * Canonical user/tenant identity used across all layers.
 * This is what identifiabl should output.
 */
export interface GatewayIdentity {
  /** Canonical subject. Often the OIDC sub claim. */
  sub: string;

  /** Normalized issuer (no trailing slash, etc.). */
  issuer: string;

  /** Optional tenant/organization/workspace identifier. */
  tenantId?: string;

  /** Optional human-friendly identifiers. */
  email?: string;
  name?: string;

  /** Optional role/tier metadata extracted from claims. */
  roles?: string[];
  scopes?: string[];
  plan?: string; // e.g. "free" | "pro" | "enterprise"

  /** Where this identity was sourced from. */
  source: IdentitySource;

  /** Original decoded JWT payload or IdP claims. */
  raw: Record<string, unknown>;
}

/**
 * Basic HTTP request metadata that is useful to all layers
 * (for audit, rate limiting, debugging, etc.).
 */
export interface GatewayRequestMeta {
  /** Correlation id for this gateway hop. */
  requestId: string;

  /** ISO timestamp of when the gateway received the request. */
  startedAt: string;

  /** HTTP method + path as seen by the gateway. */
  method: string;
  path: string;

  /** Network + client hints (optional). */
  ip?: string;
  userAgent?: string;
}

/**
 * Content-related metadata that transformabl can populate.
 * All optional so you can phase this in gradually.
 */
export interface GatewayContentMeta {
  /** Redacted / normalized prompt or body. */
  redactedInput?: unknown;

  /** High-level classification labels. */
  classifications?: string[]; // e.g. ["contains_pii", "financial"]

  /** Risk tags for policy & routing (e.g. "sensitive", "public"). */
  riskTags?: string[];

  /** Arbitrary extra metadata from NLP passes. */
  metadata?: Record<string, unknown>;
}

/**
 * Authorization / policy decision as computed by validatabl.
 */
export type AuthzDecision = "allow" | "deny";

export interface GatewayAuthzMeta {
  /** Allow/deny decision from validatabl (may be absent until evaluated). */
  decision?: AuthzDecision;
  /** Optional human-readable reason (for explicabl). */
  reason?: string;

  /** Scopes/permissions that were required and/or granted. */
  requiredScopes?: string[];
  grantedScopes?: string[];

  /** Role or policy set that was applied. */
  policyId?: string;
}

/**
 * Rate / quota / cost constraints as computed by limitabl.
 */
export type LimitDecision = "ok" | "throttled" | "quota_exceeded";

export interface GatewayLimitsMeta {
  /** Decision from limitabl (may be absent until evaluated). */
  decision?: LimitDecision;
  reason?: string;

  /** Keys used for limiting (user, tenant, ip, etc.). */
  key?: string;
  tenantKey?: string;

  /** Token / request counters if available. */
  remaining?: number;
  resetAt?: string; // ISO
}

/**
 * Routing metadata controlled by proxyabl.
 */
export interface GatewayRoutingMeta {
  /** Chosen provider/model/tool. */
  provider?: string;  // e.g. "openai", "anthropic"
  model?: string;     // e.g. "gpt-4.1-mini"
  tool?: string;      // e.g. "calendar.read"

  /** Endpoint / region / cluster hints. */
  endpoint?: string;
  region?: string;

  /** Arbitrary routing tags / decisions. */
  metadata?: Record<string, unknown>;
}

/**
 * Observability / audit fields for explicabl.
 */
export interface GatewayAuditMeta {
  /** Correlated event / trace ids. */
  eventId?: string;
  traceId?: string;
  spanId?: string;

  /** Where this event will be sent (siem, log stack, etc.). */
  destination?: string;

  /** Extra audit-relevant details. */
  metadata?: Record<string, unknown>;
}

export interface GatewayContext {
  /** HTTP-level metadata about this request. */
  request: GatewayRequestMeta; // always present once context is created

  /** Who is calling? Filled by identifiabl. */
  identity?: GatewayIdentity;

  /** Content-level metadata (redaction, classification, etc.). */
  content?: GatewayContentMeta;

  /** Authorization / policy decisions made by validatabl. */
  authz?: GatewayAuthzMeta;

  /** Rate limit / quota decisions made by limitabl. */
  limits?: GatewayLimitsMeta;

  /** Provider/model/tool routing chosen by proxyabl. */
  routing?: GatewayRoutingMeta;

  /** Audit / observability metadata for explicabl. */
  audit?: GatewayAuditMeta;

  /** Escape hatch for extensions. */
  extras?: Record<string, unknown>;
}

