import { configFromEnv, type ProxyablConfig } from "@gatewaystack/proxyabl-core";
import { createProxyablRouter } from "./router";

// NEW: add these (you will create them next)
import { createProxyablMiddleware } from "./middleware";
import { createProxyablClient } from "./client";

export { 
  createProxyablRouter, 
  createProxyablMiddleware, 
  createProxyablClient,
  configFromEnv 
};

export type { ProxyablConfig };
