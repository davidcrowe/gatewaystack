import express, { type RequestHandler } from "express";
import bodyParser from "body-parser";

import { identifiabl } from "@gatewaystack/identifiabl";
import { transformabl } from "@gatewaystack/transformabl";
import {
  protectedResourceRouter,
  requireScope,
} from "@gatewaystack/validatabl";
import { limitabl } from "@gatewaystack/limitabl";
import { toolGatewayRouter } from "@gatewaystack/proxyabl";
import { explicablRouter } from "@gatewaystack/explicabl";

import { testEchoRoutes } from "./routes/testEcho";

/**
 * GatewayStack reference server
 *
 * This app wires together all 6 governance layers:
 *  1) Identifiabl   – authentication / identity (JWT → req.user)
 *  2) Transformabl  – request transformation (PII redaction, classification)
 *  3) Validatabl    – scopes, RBAC, protected resource metadata
 *  4) Limitabl      – per-identity rate limiting / usage control
 *  5) Proxyabl      – provider routing, tool / MCP gateway
 *  6) Explicabl     – health, logging, audit, webhooks
 */
export function buildApp(env: NodeJS.ProcessEnv) {
  // -----------------------------
  // Boot & configuration
  // -----------------------------
  console.log("[boot] ENABLE_TEST_ROUTES=%s", env.ENABLE_TEST_ROUTES);
  console.log("[boot] ROUTE_ALLOWLIST=%s", env.ROUTE_ALLOWLIST);

  const DEMO = env.DEMO_MODE === "true";

  // OIDC / OAuth config (used by Identifiabl + Validatabl)
  const OAUTH_ISSUER = (DEMO ? env.OAUTH_ISSUER_DEMO : env.OAUTH_ISSUER) || "";
  const OAUTH_AUDIENCE = (DEMO ? env.OAUTH_AUDIENCE_DEMO : env.OAUTH_AUDIENCE)!;
  const OAUTH_JWKS_URI = (DEMO ? env.OAUTH_JWKS_URI_DEMO : env.OAUTH_JWKS_URI) || env.JWKS_URI_FALLBACK ||"";
  const OAUTH_SCOPES = ((DEMO ? env.OAUTH_SCOPES_DEMO : env.OAUTH_SCOPES) || "openid email profile")
    .trim()
    .split(/\s+/);

  console.log("[boot] DEMO_MODE=%s", DEMO);
  console.log("[boot] OAUTH_ISSUER=%s", OAUTH_ISSUER);
  console.log("[boot] OAUTH_AUDIENCE=%s", OAUTH_AUDIENCE);
  console.log("[boot] OAUTH_JWKS_URI=%s", OAUTH_JWKS_URI);

  // Fail fast in demo if required vars are missing
  if (DEMO && (!OAUTH_ISSUER || !OAUTH_AUDIENCE)) {
    throw new Error(
      "[demo] Missing OAUTH_*_DEMO envs. Set OAUTH_ISSUER_DEMO and OAUTH_AUDIENCE_DEMO."
    );
  }

  // Rate limiting config (limitabl)
  const windowMs = +(process.env.RATE_LIMIT_WINDOW_MS ?? 60_000);
  const limit = +(process.env.RATE_LIMIT_MAX ?? 10);

  // -----------------------------
  // Core Express setup
  // -----------------------------
  const app = express();
  app.use(bodyParser.json({ limit: "2mb" }));

  // Simple root health check (extra; explicabl has richer health)
  app.get("/", (_req, res) => res.status(200).json({ ok: true }));

  // Optional test-only routes (public)
  if (env.ENABLE_TEST_ROUTES === "true") {
    console.log("[__test__] routes enabled");
    app.use("/__test__", testEchoRoutes(env));
  }

  // -----------------------------
  // Layer 1: identifiabl (JWT → req.user)
  // -----------------------------
  const identifiablMiddleware = identifiabl({
    issuer: OAUTH_ISSUER,
    audience: OAUTH_AUDIENCE,
    jwksUri: OAUTH_JWKS_URI || undefined,
  });

  // -----------------------------
  // Layer 2: transformabl (currently a no-op)
  // -----------------------------
  const transformablMiddleware = transformabl({});

  // -----------------------------
  // Layer 3: Mount validatabl’s PRM router early for public metadata
  // validatabl is added as added via requireScope() in the protected area below
  // -----------------------------
  app.use(
    protectedResourceRouter({
      issuer: OAUTH_ISSUER.replace(/\/+$/, ""),
      audience: OAUTH_AUDIENCE,
      scopes: OAUTH_SCOPES,
    }) as unknown as RequestHandler
  );

  // -----------------------------
  // Layer 4: limitabl (per-identity rate limiting)
  // -----------------------------
  const limitablMiddleware = limitabl({ windowMs, limit });

  // -----------------------------
  // Protected area pipeline:
  // identifiabl → transformabl → limitabl → Handlers
  // -----------------------------
  app.use(
    "/protected",
    identifiablMiddleware,
    transformablMiddleware,
    limitablMiddleware
  );

  // READ example (no extra scope)
  app.get("/protected/ping", (_req, res) => res.json({ ok: true }));

  // WRITE example (requires tool:write via validatabl)
  app.post("/protected/echo", requireScope("tool:write"), (req: any, res) => {
    res.json({
      ok: true,
      sub: req.user?.sub ?? null,
      body: req.body ?? null,
    });
  });

  // -----------------------------
  // Layer 5: proxyabl (tool / MCP gateway)
  // -----------------------------
  app.use(toolGatewayRouter as unknown as RequestHandler);

  // -----------------------------
  // Layer 6: explicabl (health, logs, webhooks)
  // -----------------------------
  app.use(explicablRouter(env) as unknown as RequestHandler);

  return app;
}
