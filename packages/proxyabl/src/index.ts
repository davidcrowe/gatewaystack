// packages/proxyabl/src/index.ts
import { configFromEnv, type ProxyablConfig } from "@gatewaystack/proxyabl-core";
import { createProxyablRouter } from "./router";

export { createProxyablRouter, configFromEnv };
export type { ProxyablConfig };

export * from "./tool-gateway";
