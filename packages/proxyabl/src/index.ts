// packages/proxyabl/src/index.ts
import { configFromEnv, type ProxyablConfig } from "../../proxyabl-core/src/config";
import { createProxyablRouter } from "./router";

export { createProxyablRouter, configFromEnv };
export type { ProxyablConfig };

export * from "./tool-gateway";
