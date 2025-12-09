import { Router, type Request, type Response, type NextFunction, type RequestHandler } from "express";
import rateLimit from "express-rate-limit";
import type { ProxyablConfig, ToolScopesConfig } from "@gatewaystack/proxyabl-core";

import {
  buildWwwAuthenticate,
  fetchJsonWithRetry,
  getIssuer,
  getAudience,
  getScopesSupported,
  getJwksUri,
  getRequiredScopes,
} from "./oidc-helpers";

// 🔹 NEW: auth helpers
import {
  verifyBearerFromRequest,
  ensureToolScopesForRequest,
} from "./auth";

// 🔹 NEW: if you want a requestId like before
import { randomUUID } from "crypto";

function trimTrailingSlashes(input: string): string {
  let out = input;
  while (out.endsWith("/")) {
    out = out.slice(0, -1);
  }
  return out;
}

export function createProxyablRouter(config: ProxyablConfig): Router {
  const router = Router();

  const wellKnownRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
  }) as unknown as RequestHandler;

  const webhookRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
  }) as unknown as RequestHandler;

  // ---- Well-known endpoints ----
  router.get("/.well-known/oauth-protected-resource", (req, res, next) =>
    wkProtectedResourceHandler(config, req, res, next)
  );
  router.get("/.well-known/openid-configuration", (req, res, next) =>
    wkOpenIdConfigHandler(config, req, res, next)
  );
  router.get(
    "/.well-known/oauth-authorization-server",
    wellKnownRateLimiter,
    (req, res, next) => wkAuthzServerHandler(config, req, res, next)
  );

  // ---- MCP JSON-RPC ----
  router.post("/mcp", (req, res, next) =>
    mcpHandler(config, req, res, next)
  );
  router.options("/mcp", (req, res, next) =>
    mcpHandler(config, req, res, next)
  );

  // ---- REST tool calls (POST /:toolName) ----
  router.post("/:toolName", (req, res, next) =>
    restToolHandler(config, req, res, next)
  );

  // ---- Reverse proxy (/proxy/* or custom prefix) ----
  if (config.proxy) {
    const prefix = config.proxy.prefix || "/proxy";
    router.all(`${prefix}/*`, (req, res, next) =>
      proxyHandler(config, req, res, next)
    );
  }

  // ---- Auth0 DCR webhook (optional) ----
  if (config.auth0Dcr) {
    router.post(
      "/auth0/logs",
      webhookRateLimiter,
      (req, res, next) => auth0LogWebhookHandler(config, req, res, next)
    );
  }

  return router;
}

// For now, these are minimal placeholders.
// Next steps: replace each with your real logic from toolGatewayHandler.ts
function wkProtectedResourceHandler(
  config: ProxyablConfig,
  req: Request,
  res: Response,
  _next: NextFunction
) {
  const issuer = getIssuer(config);
  const audience = getAudience(config);

  const pathOnly = (req.originalUrl || req.url || "").split("?")[0];

  console.log("[proxyabl.wk] oauth-protected-resource", {
    path: pathOnly,
    method: req.method,
    issuer,
  });

  console.log("[proxyabl.wk.cfg]", {
    issuer: issuer ? "[configured]" : "[default]",
    audience: audience ? "[set]" : null,
    jwks_uri: getJwksUri(config) ? "[set]" : null,
    required_scopes_count: getRequiredScopes(config).length,
  });

  try {
    // Optional sanity check: try fetching issuer discovery,
    // but we don't need the response to build our payload.
    // eslint-disable-next-line @typescript-eslint/no-floating-promises
    fetchJsonWithRetry(`${issuer}/.well-known/openid-configuration`).catch((e) => {
      console.warn("[proxyabl.wk] discovery check failed", {
        message: (e as Error).message,
      });
    });

    const scopes_supported = getScopesSupported(config);

    const payload: any = {
      authorization_servers: [issuer],
      scopes_supported,
    };
    if (audience) payload.resource = audience;

    res.setHeader("Content-Type", "application/json");
    res.status(200).send(payload);
  } catch (e: any) {
    console.error("[proxyabl.wk.error]", {
      message: e?.message || String(e),
    });
    res.status(502).json({
      error: "discovery_fetch_failed",
      detail: e?.message || String(e),
    });
  }
}


async function wkOpenIdConfigHandler(
  config: ProxyablConfig,
  req: Request,
  res: Response,
  _next: NextFunction
) {
  const issuer = getIssuer(config);
  const url = `${issuer}/.well-known/openid-configuration`;

  console.log("[proxyabl.wk] openid-configuration proxy", {
    path: req.path,
    method: req.method,
    upstream: url,
  });

  try {
    const doc = await fetchJsonWithRetry(url);
    res.setHeader("Content-Type", "application/json");
    res.status(200).send(doc);
  } catch (e: any) {
    console.error("[proxyabl.wk.error]", {
      message: e?.message || String(e),
    });
    res.status(502).json({
      error: "discovery_fetch_failed",
      detail: e?.message || String(e),
    });
  }
}


async function wkAuthzServerHandler(
  config: ProxyablConfig,
  req: Request,
  res: Response,
  _next: NextFunction
) {
  const issuer = getIssuer(config);
  const url = `${issuer}/.well-known/oauth-authorization-server`;

  console.log("[proxyabl.wk] oauth-authorization-server proxy", {
    path: req.path,
    method: req.method,
    upstream: url,
  });

  try {
    const doc = await fetchJsonWithRetry(url);
    res.setHeader("Content-Type", "application/json");
    res.status(200).send(doc);
  } catch (e: any) {
    console.error("[proxyabl.wk.error]", {
      message: e?.message || String(e),
    });
    res.status(502).json({
      error: "discovery_fetch_failed",
      detail: e?.message || String(e),
    });
  }
}


// ---- MCP JSON-RPC helpers ----

type JsonRpcReq = {
  jsonrpc: "2.0";
  id?: string | number | null;
  method: string;
  params?: any;
};

type JsonRpcRes =
  | { jsonrpc: "2.0"; id: string | number | null; result: any }
  | {
      jsonrpc: "2.0";
      id: string | number | null;
      error: { code: number; message: string; data?: any };
    };

function jsonRpcResult(id: any, result: any): JsonRpcRes {
  return { jsonrpc: "2.0", id: id ?? null, result };
}

function jsonRpcError(
  id: any,
  code: number,
  message: string,
  data?: any
): JsonRpcRes {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message, data } };
}


async function mcpHandler(
  config: ProxyablConfig,
  req: Request,
  res: Response,
  _next: NextFunction
) {
  // We always speak JSON
  res.setHeader("Content-Type", "application/json");

  // OPTIONS → CORS preflight
  if (req.method === "OPTIONS") {
    res.status(204).end();
    return;
  }

  // Only POST is allowed beyond this point
  if (req.method !== "POST") {
    res
      .status(405)
      .json({ jsonrpc: "2.0", id: null, error: { code: -32600, message: "Method not allowed" } });
    return;
  }

  // Parse JSON-RPC body
  let rpc: JsonRpcReq;
  try {
    rpc =
      typeof req.body === "string"
        ? (JSON.parse(req.body) as JsonRpcReq)
        : (req.body as JsonRpcReq);
  } catch {
    res.status(400).json(jsonRpcError(null, -32700, "Parse error"));
    return;
  }

  if (!rpc || rpc.jsonrpc !== "2.0" || typeof rpc.method !== "string") {
    res
      .status(400)
      .json(jsonRpcError(rpc?.id ?? null, -32600, "Invalid Request"));
    return;
  }

  // --- 1) initialize → no auth required
  if (rpc.method === "initialize") {
    const result = {
      protocolVersion: "2025-06-18",
      capabilities: { tools: { listChanged: false } },
      serverInfo: { name: "proxyabl-gateway", version: "0.1.0" },
    };
    res.status(200).json(jsonRpcResult(rpc.id ?? null, result));
    return;
  }

  // --- 2) notifications/initialized → ack-only
  if (rpc.method === "notifications/initialized") {
    res.status(202).end();
    return;
  }

  // From here on, methods are authenticated
  // From here on, methods are authenticated
  const functionsBaseRaw = config.functionsBase || "";
  const functionsBase = trimTrailingSlashes(functionsBaseRaw);
  if (!functionsBase) {
    res.status(500).json(
      jsonRpcError(rpc.id ?? null, -32000, "functionsBase not configured")
    );
    return;
  }

  // Helper: verify bearer + scopes, shared by tools/list and tools/call
  const ensureAuth = async (toolNameForScopes?: string) => {
    try {
      const identity = await verifyBearerFromRequest(config, req);

      if (toolNameForScopes) {
        ensureToolScopesForRequest(config, toolNameForScopes, identity.scopes);
      }

      return identity;
    } catch (e: any) {
      const status = Number(e?.status) || 401;
      const www = e?.www || buildWwwAuthenticate(config, req);
      res.setHeader("WWW-Authenticate", www);
      res
        .status(status)
        .json(
          jsonRpcError(
            rpc.id ?? null,
            -32001,
            e?.message || "Unauthorized",
            { code: e?.code || "AUTH_ERROR" }
          )
        );
      return undefined;
    }
  };

  // --- 3) tools/list
  if (rpc.method === "tools/list") {
    const identity = await ensureAuth(); // auth required, but no specific tool scopes yet
    if (!identity) return; // response already sent

    const toolScopes: ToolScopesConfig = config.toolScopes ?? {};

    const tools = Object.entries(toolScopes).map(([name, scopes]) => {
    const required = Array.isArray(scopes) ? scopes : [];

    const inputSchema = {
        $schema: "http://json-schema.org/draft-07/schema#",
        type: "object",
        additionalProperties: true,
    };

    const securitySchemes =
        required.length > 0
        ? [{ type: "oauth2" as const, scopes: required }]
        : [{ type: "noauth" as const }];

    return {
        name,
        title: name.replace(/([A-Z])/g, " $1").trim(),
        description: name,
        inputSchema,
        input_schema: inputSchema,
        requiredScopes: required,
        securitySchemes,
        executable: true,
    };
    });

    res.status(200).json(
      jsonRpcResult(rpc.id ?? null, {
        tools,
      })
    );
    return;
  }

  // --- 4) tools/call
  if (rpc.method === "tools/call") {
    const nameRaw = rpc.params?.name;
    const args = rpc.params?.arguments ?? {};

    if (typeof nameRaw !== "string") {
      res
        .status(400)
        .json(
          jsonRpcError(
            rpc.id ?? null,
            -32602,
            "Invalid tool name",
            { code: "INVALID_TOOL_NAME" }
          )
        );
      return;
    }

    let toolName: string;
    try {
      toolName = sanitizeToolName(config, nameRaw);
    } catch (e: any) {
      const status = Number(e?.status) || 400;
      res.status(status).json(
        jsonRpcError(
          rpc.id ?? null,
          -32602,
          e?.message || "Invalid tool name",
          { code: e?.code || "INVALID_TOOL_NAME" }
        )
      );
      return;
    }

    const identity = await ensureAuth(toolName);
    if (!identity) return; // response already sent

    const requestId = req.header("x-request-id") || randomUUID();
    const url = `${functionsBase}/${toolName}`;

    const upstream = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-request-id": requestId,
        // later you can add x-user-uid / x-gateway-sig if you want
      },
      body: JSON.stringify(args),
    } as any);

    const ct = upstream.headers.get("content-type") || "";
    const payloadOut = ct.includes("json")
      ? await upstream.json()
      : await upstream.text();

    if (!upstream.ok) {
      res.status(200).json(
        jsonRpcResult(rpc.id ?? null, {
          isError: true,
          content: [
            {
              type: "error",
              error: { status: upstream.status, body: payloadOut },
            },
          ],
        })
      );
      return;
    }

    res.status(200).json(
      jsonRpcResult(rpc.id ?? null, {
        isError: false,
        content: [{ type: "output_json", json: payloadOut }],
      })
    );
    return;
  }

  // --- 5) Unknown method
  res
    .status(400)
    .json(
      jsonRpcError(
        rpc.id ?? null,
        -32601,
        `Method not found: ${rpc.method}`
      )
    );
}


function toolNameFromPath(path: string): string | null {
  const parts = path.split("/").filter(Boolean);
  return parts.length ? parts[parts.length - 1] : null;
}

/**
 * Only allow "safe" tool names and require that they exist in config.toolScopes.
 * Mirrors your old sanitizeFunctionName behavior.
 */
function sanitizeToolName(config: ProxyablConfig, raw: string): string {
  if (!/^[a-zA-Z0-9_-]+$/.test(raw)) {
    const err: any = new Error("INVALID_TOOL_NAME");
    err.status = 400;
    err.code = "INVALID_TOOL_NAME";
    throw err;
  }

  const toolScopes = config.toolScopes ?? {};
  if (!toolScopes[raw]) {
    const err: any = new Error(`UNKNOWN_TOOL:${raw}`);
    err.status = 404;
    err.code = "UNKNOWN_TOOL";
    throw err;
  }

  return raw;
}

async function restToolHandler(
  config: ProxyablConfig,
  req: Request,
  res: Response,
  _next: NextFunction
) {
  if (req.method !== "POST") {
    res.status(405).json({ ok: false, error: { code: "METHOD_NOT_ALLOWED" } });
    return;
  }

  const requestId = req.header("x-request-id") || randomUUID();
  const started = Date.now();

  try {
    // 1) Parse + sanitize tool name from path
    const rawName = toolNameFromPath(req.path);
    if (!rawName) {
      res.status(400).json({
        ok: false,
        error: { code: "NO_TOOL", message: "Missing tool name" },
        requestId,
      });
      return;
    }

    let toolName: string;
    try {
      toolName = sanitizeToolName(config, rawName);
    } catch (e: any) {
      const status = Number(e?.status) || 400;
      res.status(status).json({
        ok: false,
        error: { code: e?.code || "INVALID_TOOL_NAME", message: e?.message || "Invalid tool name" },
        requestId,
      });
      return;
    }

    // 2) Verify Bearer token + populate GatewayContext.identity
    let identity;
    try {
      identity = await verifyBearerFromRequest(config, req);
    } catch (e: any) {
      const status = Number(e?.status) || 401;
      const www = e?.www || buildWwwAuthenticate(config, req);
      res.setHeader("WWW-Authenticate", www);
      res.status(status).json({
        ok: false,
        error: { code: e?.code || "AUTH_ERROR", message: e?.message || "Unauthorized" },
        requestId,
      });
      return;
    }

    // 3) Enforce tool scopes
    try {
      ensureToolScopesForRequest(config, toolName, identity.scopes);
    } catch (e: any) {
      const status = Number(e?.status) || 403;
      res.status(status).json({
        ok: false,
        error: { code: e?.code || "INSUFFICIENT_SCOPE", message: e?.message || "Insufficient scope" },
        requestId,
      });
      return;
    }

    // 4) Call upstream tool function
    const baseRaw = config.functionsBase || "";
    const base = trimTrailingSlashes(baseRaw);
    if (!base) {
      res.status(500).json({
        ok: false,
        error: { code: "MISSING_FUNCTIONS_BASE", message: "functionsBase not configured in ProxyablConfig" },
        requestId,
      });
      return;
    }

    const url = `${base}/${toolName}`;

    const upstream = await fetch(url, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-request-id": requestId,
        // you can add additional headers here later (x-user-uid, x-gateway-sig, etc.)
      },
      body: JSON.stringify(req.body ?? {}),
    } as any);

    const ct = upstream.headers.get("content-type") || "";
    const payloadOut = ct.includes("json") ? await upstream.json() : await upstream.text();
    const elapsedMs = Date.now() - started;

    if (!upstream.ok) {
      res.status(upstream.status).json({
        ok: false,
        error: {
          code: `FN_${upstream.status}`,
          message: "Function error",
          details: payloadOut,
        },
        requestId,
        elapsedMs,
        sub: identity.sub,
      });
      return;
    }

    res.status(200).json({
      ok: true,
      data: payloadOut,
      requestId,
      elapsedMs,
      sub: identity.sub,
    });
  } catch (e: any) {
    const status = Number(e?.status) || 500;
    console.error("[proxyabl.rest:error]", {
      status,
      message: e?.message || String(e),
    });
    res.status(status).json({
      ok: false,
      error: { code: e?.code || "GATEWAY_ERROR", message: e?.message || String(e) },
      requestId,
    });
  }
}

// ---- Reverse proxy helpers ----

function getProxyTargetUrl(config: ProxyablConfig): URL | null {
  const target = config.proxy?.target;
  if (!target) return null;

  try {
    const u = new URL(target);
    if (!/^https?:$/.test(u.protocol)) {
      console.error("[proxyabl.proxy] PROXY target must be http or https");
      return null;
    }
    // Basic hostname sanity: only letters, digits, dot, dash
    if (!/^[a-zA-Z0-9.-]+$/.test(u.hostname)) {
      console.error("[proxyabl.proxy] invalid proxy hostname:", u.hostname);
      return null;
    }
    return u;
  } catch (e) {
    console.error("[proxyabl.proxy] invalid proxy target:", target, e);
    return null;
  }
}

/**
 * Normalize a configured allowedPath into a safe prefix:
 * - ensure leading slash
 * - only allow [a-zA-Z0-9/_-]
 */
function normalizeAllowedPrefix(prefix: string): string | null {
  if (typeof prefix !== "string") return null;

  let p = prefix.trim();
  if (!p) return null;

  // ensure leading slash
  p = "/" + p.replace(/^\/+/, "");

  // Only allow safe characters in paths
  if (!/^\/[a-zA-Z0-9/_-]*$/.test(p)) {
    console.warn("[proxyabl.proxy] ignoring invalid allowedPath:", prefix);
    return null;
  }

  return p;
}

/**
 * Get the allowlisted upstream path prefixes.
 * If not provided or invalid, default to ["/"] (everything).
 */
function getProxyAllowedPaths(config: ProxyablConfig): string[] {
  const fromConfig = config.proxy?.allowedPaths;
  if (fromConfig && fromConfig.length) {
    const cleaned = fromConfig
      .map(normalizeAllowedPrefix)
      .filter((p): p is string => Boolean(p));
    if (cleaned.length) return cleaned;
  }
  return ["/"];
}


/**
 * Normalize and sanitize the upstream path tail.
 * Always returns a path (never a URL), forbids \"//\", \"://\", and \"..\".
 */
function sanitizeProxyPath(rawTail: string): string {
  let p = rawTail || "/";

  // Normalize: ensure leading slash
  p = "/" + p.replace(/^\/+/, "");

  // Block attempts to smuggle in full URLs or schemes
  if (p.startsWith("//") || p.includes("://")) {
    const err: any = new Error("INVALID_UPSTREAM_PATH");
    err.status = 400;
    err.code = "INVALID_UPSTREAM_PATH";
    throw err;
  }

  // Avoid .. path traversal
  if (p.includes("..")) {
    const err: any = new Error("INVALID_UPSTREAM_PATH");
    err.status = 400;
    err.code = "INVALID_UPSTREAM_PATH";
    throw err;
  }

  return p;
}

/**
 * Enforce that the path is under one of the allowed prefixes.
 * - Exact match: "/foo"
 * - Prefix match: "/foo/" matches "/foo/bar", "/foo/baz", etc.
 */
function enforceProxyPathAllowlist(
  path: string,
  allowedPrefixes: string[]
): void {
  const ok = allowedPrefixes.some((prefix) => {
    const pref = prefix.startsWith("/") ? prefix : `/${prefix}`;
    if (pref.endsWith("/")) {
      return path === pref.slice(0, -1) || path.startsWith(pref);
    }
    return path === pref || path.startsWith(pref + "/");
  });

  if (!ok) {
    const err: any = new Error("PROXY_PATH_NOT_ALLOWED");
    err.status = 403;
    err.code = "PROXY_PATH_NOT_ALLOWED";
    throw err;
  }
}

async function proxyHandler(
  config: ProxyablConfig,
  req: Request,
  res: Response,
  _next: NextFunction
) {
  const proxyCfg = config.proxy;
  const baseUrl = getProxyTargetUrl(config);

  if (!proxyCfg || !baseUrl) {
    res.status(501).json({
      ok: false,
      error: "proxy_not_configured",
    });
    return;
  }

  try {
    // 🔐 1) Authenticate the caller
    const identity = await verifyBearerFromRequest(config, req);
    const userId = identity.sub;

    const allowedPaths = getProxyAllowedPaths(config);

    // 2) Strip the gateway prefix and sanitize the tail
    const prefix = proxyCfg.prefix || "/proxy";
    const rawTail = req.path.slice(prefix.length) || "/";
    const tail = sanitizeProxyPath(rawTail);

    // 3) Enforce allowlist BEFORE constructing URL
    enforceProxyPathAllowlist(tail, allowedPaths);

    // 4) Build upstream URL anchored to validated baseUrl
    const urlObj = new URL(tail, baseUrl);

    // Extra SSRF guard: ensure hostname + protocol still match the configured target
    if (urlObj.hostname !== baseUrl.hostname || urlObj.protocol !== baseUrl.protocol) {
      console.warn("[proxyabl.proxy] host/protocol mismatch after URL construction", {
        baseHost: baseUrl.hostname,
        baseProto: baseUrl.protocol,
        urlHost: urlObj.hostname,
        urlProto: urlObj.protocol,
      });

      res.status(400).json({
        ok: false,
        error: "invalid_upstream_url",
        detail: "Upstream URL host/protocol mismatch",
      });
      return;
    }

    // Copy original query params
    for (const [k, v] of Object.entries(req.query)) {
      if (Array.isArray(v)) {
        v.forEach((x) => urlObj.searchParams.append(k, String(x)));
      } else if (v != null) {
        urlObj.searchParams.append(k, String(v));
      }
    }

    // Inject user id into query if configured
    if (proxyCfg.injectQuery) {
      urlObj.searchParams.set(proxyCfg.injectQuery, userId);
    }

    // 5) Build upstream headers
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(req.headers)) {
      const key = k.toLowerCase();
      if (
        key === "host" ||
        key === "connection" ||
        key === "content-length" ||
        key === "transfer-encoding" ||
        key === "authorization"
      ) {
        continue;
      }
      headers[key] = Array.isArray(v) ? v.join(", ") : (v as string);
    }

    // Inject user id into header if configured
    if (proxyCfg.injectHeader) {
      headers[proxyCfg.injectHeader.toLowerCase()] = userId;
    }

    const method = req.method.toUpperCase();
    const hasBody = !["GET", "HEAD"].includes(method);
    const body =
      hasBody && req.body ? JSON.stringify(req.body) : undefined;
    if (body && !headers["content-type"]) {
      headers["content-type"] = "application/json";
    }

    // 6) Timeout + fetch
    const controller = new AbortController();
    const timeoutMs = proxyCfg.timeoutMs ?? 5000;
    const t = setTimeout(() => controller.abort(), timeoutMs);

    // codeql[js/server-side-request-forgery]: upstream URL is constrained by a validated baseUrl + strict path allowlist; tail is sanitized to disallow protocols, hostnames, and traversal.
    const upstream = await fetch(urlObj.toString(), {
      method,
      headers,
      body,
      signal: controller.signal,
    } as any);

    clearTimeout(t);

    // 7) Stream response back
    res.status(upstream.status);
    upstream.headers.forEach((val, key) => {
      const k = key.toLowerCase();
      if (k === "content-length" || k === "transfer-encoding" || k === "connection") {
        return;
      }
      res.setHeader(key, val);
    });

    const buf = Buffer.from(await upstream.arrayBuffer());
    res.end(buf);
  } catch (e: any) {
    if (e?.name === "AbortError") {
      res.status(502).json({ error: "upstream_timeout" });
      return;
    }

    const status = Number(e?.status) || 502;
    console.error("[proxyabl.proxy.error]", {
      status,
      code: e?.code,
      message: e?.message,
    });

    res.status(status).json({ error: e?.code || "proxy_failed" });
  }
}

// ---- Auth0 DCR helpers ----

interface OAuthTokenRes {
  access_token: string;
  token_type?: string;
  expires_in?: number;
}

function getAuth0DcrConfig(config: ProxyablConfig) {
  const dcr = config.auth0Dcr;
  if (!dcr) {
    throw new Error("auth0Dcr_not_configured");
  }
  return dcr;
}

function sanitizeMgmtClientId(id: string): string {
  if (typeof id !== "string") {
    throw new Error("invalid_client_id_type");
  }
  // Auth0 client_ids are URL-safe base64-ish: letters, digits, - and _
  if (!/^[a-zA-Z0-9_-]+$/.test(id)) {
    throw new Error("invalid_client_id_format");
  }
  return id;
}

function auth0MgmtUrl(dcrCfg: ReturnType<typeof getAuth0DcrConfig>, path: string): string {
  const domain = (dcrCfg.mgmtDomain || "").trim();
  if (!domain) {
    throw new Error("MGMT_DOMAIN_not_set");
  }
  // Defensive: only allow hostname-style content in domain
  if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {
    throw new Error(`invalid_MGMT_DOMAIN:${domain}`);
  }
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return `https://${domain}${normalizedPath}`;
}

async function getMgmtToken(
  config: ProxyablConfig
): Promise<string> {
  const dcrCfg = getAuth0DcrConfig(config);

  const r = await fetch(
    auth0MgmtUrl(dcrCfg, "/oauth/token"),
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        grant_type: "client_credentials",
        client_id: dcrCfg.clientId,
        client_secret: dcrCfg.clientSecret,
        audience: auth0MgmtUrl(dcrCfg, "/api/v2/"),
      }),
    } as any
  );

  if (!r.ok) {
    throw new Error(`mgmt_token_http_${r.status}`);
  }

  const j = (await r.json()) as OAuthTokenRes;
  if (!j?.access_token) {
    throw new Error("mgmt_token_missing_access_token");
  }
  return j.access_token;
}


async function promoteClient(
  config: ProxyablConfig,
  mgmtToken: string,
  clientId: string
) {
  const dcrCfg = getAuth0DcrConfig(config);

  const patchBody = {
    app_type: "regular_web",
    is_first_party: true,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
  };

  const safeClientId = sanitizeMgmtClientId(clientId);

  const r = await fetch(
    auth0MgmtUrl(dcrCfg, `/api/v2/clients/${encodeURIComponent(safeClientId)}`),
    {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${mgmtToken}`,
      },
      body: JSON.stringify(patchBody),
    } as any
  );

  if (!r.ok) {
    console.error("[proxyabl.dcr.promoteClient:error]", {
      status: r.status,
      client_id_suffix: safeClientId.slice(-5),
    });
    throw new Error(`promote_http_${r.status}`);
  }
}

async function enableGoogleForClient(
  config: ProxyablConfig,
  mgmtToken: string,
  clientId: string
) {
  const dcrCfg = getAuth0DcrConfig(config);
  const connectionName = dcrCfg.googleConnectionName || "google-oauth2";

  // 1) find the connection id for google-oauth2
  const rc = await fetch(
    auth0MgmtUrl(dcrCfg, `/api/v2/connections?name=${encodeURIComponent(connectionName)}`),
    {
      headers: { authorization: `Bearer ${mgmtToken}` },
    } as any
  );
  if (!rc.ok) throw new Error(`conn_lookup_http_${rc.status}`);

  const arr = (await rc.json()) as Array<{ id?: string; enabled_clients?: string[] }>;
  const conn = Array.isArray(arr) ? arr[0] : null;
  if (!conn || !conn.id) throw new Error(`connection_not_found:${connectionName}`);

  // 2) add clientId to enabled_clients (idempotent)
  const enabled = new Set<string>(Array.isArray(conn.enabled_clients) ? conn.enabled_clients : []);
  enabled.add(clientId);

  const rp = await fetch(
    auth0MgmtUrl(dcrCfg, `/api/v2/connections/${conn.id}`),
    {
      method: "PATCH",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${mgmtToken}`,
      },
      body: JSON.stringify({ enabled_clients: Array.from(enabled) }),
    } as any
  );
  if (!rp.ok) {
    console.error("[proxyabl.dcr.enableGoogleForClient:error]", {
      status: rp.status,
      client_id_suffix: clientId.slice(-5),
    });
    throw new Error(`conn_patch_http_${rp.status}`);
  }
}

function unwrapAuth0Event(ev: any): any {
  // Auth0 Log Streams often send { data: <actual-log> }
  return ev && typeof ev === "object" && ev.data && typeof ev.data === "object"
    ? ev.data
    : ev;
}

function evtPath(e: any): string {
  return String(
    e?.details?.request?.path ||
      e?.details?.request?.url ||
      e?.http?.request?.path ||
      ""
  ).toLowerCase();
}

function isDcrEventRaw(ev: any): boolean {
  const e = unwrapAuth0Event(ev);
  const type = String(e?.type || "").toLowerCase(); // e.g., "sapi"
  const desc = String(e?.description || "").toLowerCase(); // "dynamic client registration"
  const path = evtPath(e);
  const method = String(e?.details?.request?.method || e?.http?.method || "").toUpperCase();

  return (
    // classic text
    (type === "sapi" && desc.includes("dynamic client registration")) ||
    // OIDC DCR endpoint
    path.includes("/oidc/register") ||
    // some tenants log it as client creation via Mgmt API
    (method === "POST" &&
      (path === "/api/v2/clients" || path.endsWith("/api/v2/clients")))
  );
}

function extractClientIdFromDcrRaw(ev: any): string | null {
  const e = unwrapAuth0Event(ev);
  return (
    e?.details?.response?.body?.client_id ??
    e?.client_id ??
    e?.details?.request?.body?.client_id ??
    null
  );
}

async function findNewestChatGPTClientId(
  config: ProxyablConfig,
  mgmtToken: string
): Promise<string | null> {
  const dcrCfg = getAuth0DcrConfig(config);
  const url =
    auth0MgmtUrl(dcrCfg, "/api/v2/clients") +
    "?is_global=false&per_page=10&sort=created_at:-1" +
    "&fields=client_id,name,created_at,app_type,grant_types,token_endpoint_auth_method" +
    "&include_fields=true";

  const r = await fetch(url, {
    headers: { authorization: `Bearer ${mgmtToken}` },
  } as any);

  if (!r.ok) {
    console.warn("[proxyabl.dcr] clients list failed", { status: r.status });
    return null;
  }

  const arr = (await r.json()) as Array<any>;
  const now = Date.now();

  for (const c of arr) {
    const name = String(c?.name || "");
    const createdAt = Date.parse(c?.created_at || "");
    const within5min = isFinite(createdAt) && now - createdAt < 5 * 60 * 1000;
    const looksLikeDcr =
      name.toLowerCase().startsWith("chatgpt") ||
      name.toLowerCase().includes("chat gpt");
    const publicPkce =
      c?.token_endpoint_auth_method === "none" &&
      Array.isArray(c?.grant_types) &&
      c.grant_types.includes("authorization_code");

    if (within5min && looksLikeDcr && publicPkce && c?.client_id) {
      return c.client_id as string;
    }
  }

  return null;
}

async function auth0LogWebhookHandler(
  config: ProxyablConfig,
  req: Request,
  res: Response,
  _next: NextFunction
) {
  try {
    const dcrCfg = getAuth0DcrConfig(config);

    // 1) Shared-secret auth
    const auth = req.header("authorization") || "";
    if (auth !== `Bearer ${dcrCfg.logWebhookSecret}`) {
      res.status(401).json({ ok: false, error: "unauthorized" });
      return;
    }

    // 2) Not configured → advertise clearly (nice for OSS quickstarts)
    if (
    !dcrCfg.mgmtDomain ||
    !dcrCfg.clientId ||
    !dcrCfg.clientSecret
    ) {
    res.status(501).json({
        ok: false,
        error: "not_configured",
        detail:
        "Set auth0Dcr.mgmtDomain, clientId, clientSecret to enable DCR promotion.",
    });
    return;
    }


    // 3) Parse events
    let parsed: unknown = req.body;
    if (typeof parsed === "string") {
      try {
        parsed = JSON.parse(parsed);
      } catch {
        // ignore parse error, treat as a single opaque event
      }
    }

    const events: any[] = Array.isArray(parsed)
      ? (parsed as any[])
      : [parsed as any];
    const dcrEvents = events.filter(isDcrEventRaw);

    if (dcrEvents.length === 0) {
      res.status(200).json({ ok: true, filtered: true });
      return;
    }

    // 4) Promote each DCR'ed client
    const mgmtToken = await getMgmtToken(config);

    for (const raw of dcrEvents) {
      let cid = extractClientIdFromDcrRaw(raw);
      if (!cid) {
        console.warn("[proxyabl.dcr] no client_id in event; attempting fallback lookup");
        cid = await findNewestChatGPTClientId(config, mgmtToken);
      }
      if (!cid) {
        console.warn("[proxyabl.dcr] could not determine client_id; skipping event");
        continue;
      }

      console.log("[proxyabl.dcr] promoting client", { client_id: cid });

      try {
        await promoteClient(config, mgmtToken, cid);
      } catch (e: any) {
        const msg = String(e?.message || "");
        if (msg.startsWith("promote_http_404")) {
          console.warn(
            "[proxyabl.dcr] 404 promoting client; retrying with fallback search"
          );
          const alt = await findNewestChatGPTClientId(config, mgmtToken);
          if (alt && alt !== cid) {
            console.log("[proxyabl.dcr] retry promoting", { client_id: alt });
            await promoteClient(config, mgmtToken, alt);
            cid = alt;
          } else {
            throw e;
          }
        } else {
          throw e;
        }
      }

      await enableGoogleForClient(config, mgmtToken, cid);
      console.log("[proxyabl.dcr] promoted+enabled", { client_id: cid });
    }

    res.status(200).json({ ok: true, promoted: dcrEvents.length });
  } catch (e: any) {
    console.error("[proxyabl.dcr:error]", {
      message: e?.message || String(e),
    });
    res.status(500).json({ ok: false, error: "dcr_failed" });
  }
}

