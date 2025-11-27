// packages/request-context/src/index.ts

export * from "./types";

import type {
  GatewayContext,
  GatewayRequestMeta,
} from "./types";

export function createGatewayContext(
  overrides: Partial<GatewayContext> = {}
): GatewayContext {
  const reqOverrides: Partial<GatewayRequestMeta> = overrides.request ?? {};

  const request: GatewayRequestMeta = {
    requestId:
      reqOverrides.requestId ??
      `gw_${Math.random().toString(36).slice(2)}`,
    startedAt: reqOverrides.startedAt ?? new Date().toISOString(),
    method: reqOverrides.method ?? "UNKNOWN",
    path: reqOverrides.path ?? "UNKNOWN",
    ip: reqOverrides.ip,
    userAgent: reqOverrides.userAgent,
  };

  const base: GatewayContext = {
    request,
    identity: overrides.identity,
    content: overrides.content,
    authz: overrides.authz,
    limits: overrides.limits,
    routing: overrides.routing,
    audit: overrides.audit,
    extras: overrides.extras ?? {},
  };

  return base;
}

export function mergeGatewayContext(
  base: GatewayContext,
  updates: Partial<GatewayContext>
): GatewayContext {
  const request: GatewayRequestMeta = {
    ...base.request,
    ...(updates.request ?? {}),
  };

  return {
    ...base,
    ...updates,
    request,
    identity: updates.identity ?? base.identity,
    content: { ...base.content, ...updates.content },
    authz: { ...base.authz, ...updates.authz },
    limits: { ...base.limits, ...updates.limits },
    routing: { ...base.routing, ...updates.routing },
    audit: { ...base.audit, ...updates.audit },
    extras: { ...(base.extras ?? {}), ...(updates.extras ?? {}) },
  };
}
