// packages/proxyabl/src/index.ts

import { configFromEnv, type ProxyablConfig } from "@gatewaystack/proxyabl-core";
import { createProxyablRouter } from "./router.js";

// NEW: add these (you will create them next)
import { createProxyablMiddleware } from "./middleware.js";
import { createProxyablClient } from "./client.js";

// 🔹 NEW: normalization helpers
import {
  normalizeProxyablResult,
  getContentTypeFromProxyResponse,
  readBodyFromProxyResponse,
  isResponseLike,
} from "./result.js";

export {
  createProxyablRouter,
  createProxyablMiddleware,
  createProxyablClient,
  configFromEnv,
  // 🔹 export helpers
  normalizeProxyablResult,
  getContentTypeFromProxyResponse,
  readBodyFromProxyResponse,
  isResponseLike,
};

export type { ProxyablConfig };

