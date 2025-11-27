"use strict";
// packages/request-context/src/index.ts
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createGatewayContext = createGatewayContext;
exports.mergeGatewayContext = mergeGatewayContext;
__exportStar(require("./types"), exports);
function createGatewayContext(overrides = {}) {
    const reqOverrides = overrides.request ?? {};
    const request = {
        requestId: reqOverrides.requestId ??
            `gw_${Math.random().toString(36).slice(2)}`,
        startedAt: reqOverrides.startedAt ?? new Date().toISOString(),
        method: reqOverrides.method ?? "UNKNOWN",
        path: reqOverrides.path ?? "UNKNOWN",
        ip: reqOverrides.ip,
        userAgent: reqOverrides.userAgent,
    };
    const base = {
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
function mergeGatewayContext(base, updates) {
    const request = {
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
