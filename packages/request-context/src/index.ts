// packages/request-context/src/index.ts

export * from "./types";

import type {
  GatewayContext,
  GatewayRequestMeta,
} from "./types";

// New helper for "overrides" shape
type GatewayContextOverrides = Omit<Partial<GatewayContext>, "request"> & {
  request?: Partial<GatewayRequestMeta>;
};

export function createGatewayContext(
  overrides: GatewayContextOverrides = {}
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

// ADD THIS BELOW mergeGatewayContext in packages/request-context/src/index.ts

import { AsyncLocalStorage } from "async_hooks";

const gatewayAls = new AsyncLocalStorage<GatewayContext>();

/**
 * Run a function with a fresh GatewayContext bound to the current async call chain.
 * Typically called once per inbound HTTP request by identifiabl middleware.
 */
export function runWithGatewayContext<T>(
  overrides: GatewayContextOverrides,
  fn: () => T
): T {
  const ctx = createGatewayContext(overrides);
  return gatewayAls.run(ctx, fn);
}

/**
 * Get the current GatewayContext (if any) for this async call chain.
 * Returns undefined if called outside runWithGatewayContext.
 */
export function getGatewayContext(): GatewayContext | undefined {
  return gatewayAls.getStore();
}

/**
 * Merge updates into the current context in-place.
 * (Useful for later layers like transformabl, validatabl, limitabl, etc.)
 */
export function updateGatewayContext(
  updates: Partial<GatewayContext>
): void {
  const current = gatewayAls.getStore();
  if (!current) return;

  const merged = mergeGatewayContext(current, updates);

  // Mutate in place so references held elsewhere stay valid.
  Object.assign(current, merged);
}
