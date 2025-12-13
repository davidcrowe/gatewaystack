// src/routes/testEcho.ts
import express from "express";
import type { Request, Response, NextFunction } from "express";
import { createRemoteJWKSet, jwtVerify } from "jose";
import rateLimit from "express-rate-limit";

// Read allowlist from env the same way your handler does (or import your util if you have one)
function parseAllowlist(env: NodeJS.ProcessEnv): Record<string, string[]> {
  try {
    const raw = env.TOOL_SCOPE_ALLOWLIST_JSON || "{}";
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

// ---- Rate limiting for test echo routes ----
function keyFromReq(req: Request): string {
  const xf = req.get?.("x-forwarded-for");
  if (typeof xf === "string") {
    // Take first IP in X-Forwarded-For
    return xf.split(",")[0].trim();
  }

  // Fallbacks
  return (
    (req.ip as string) ||
    // @ts-ignore – older Express types
    (req.connection && (req.connection as any).remoteAddress) ||
    "unknown"
  );
}


function createTestEchoLimiter(env: NodeJS.ProcessEnv): express.RequestHandler {
  const windowMs = +(env.TEST_ECHO_WINDOW_MS || 60_000); // 1 minute default
  const max = +(env.TEST_ECHO_MAX_PER_WINDOW || 60);     // 60 reqs/min default

  const limiter = rateLimit({
    windowMs,
    max,
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: keyFromReq,
  });

  // bridge any subtle @types/express mismatch
  return limiter as unknown as express.RequestHandler;
}

function requireJwt(env: NodeJS.ProcessEnv) {
  const issuer = env.AUTH0_ISSUER || env.OIDC_ISSUER;
  const audience = env.AUTH0_AUDIENCE || env.OIDC_AUDIENCE;
  const jwksUri = env.AUTH0_JWKS_URI || env.OIDC_JWKS_URI;
  if (!issuer || !audience || !jwksUri) throw new Error("Missing OIDC env for tests");

  const JWKS = createRemoteJWKSet(new URL(jwksUri));

  return async (req: Request, res: Response, next: NextFunction) => {
    try {
      const auth = req.headers.authorization || "";
      const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
      if (!token) return res.status(401).json({ error: "missing_bearer" });

      const { payload, protectedHeader } = await jwtVerify(token, JWKS, {
        issuer,
        audience,
      });
      (req as any).user = payload;
      (req as any).header = protectedHeader;
      next();
    } catch (e: any) {
      return res.status(401).json({ error: "invalid_token", detail: e?.message });
    }
  };
}

function requireScope(env: NodeJS.ProcessEnv) {
  const allow = parseAllowlist(env);
  return (req: Request, res: Response, next: NextFunction) => {
    // The client will pass the *required* scope for the target route via header for tests
    // (e.g., x-required-scope: contacts.read)
    const required = String(req.headers["x-required-scope"] || "");
    const method = req.method.toUpperCase();
    const path = req.path; // "/echo" etc.

    // Map this test route to a synthetic resource, e.g. GET:/__test__/echo
    const resourceKey = `${method}:${req.baseUrl}${path}`; // e.g. "GET:/__test__/echo"

    // Extract scopes from token (space-delimited)
    const tokenScopes = String((req as any).user?.scope || "").split(/\s+/).filter(Boolean);
    const allowedRoutes = new Set<string>();
    for (const s of tokenScopes) {
      (allow[s] || []).forEach(r => allowedRoutes.add(r));
    }

    if (!required) return res.status(400).json({ error: "missing_required_scope_header" });
    if (!tokenScopes.includes(required)) {
      return res.status(403).json({ error: "insufficient_scope", need: required, have: tokenScopes });
    }
    if (!allowedRoutes.has(resourceKey)) {
      return res.status(403).json({ error: "route_not_in_allowlist", route: resourceKey, allow: [...allowedRoutes] });
    }
    next();
  };
}

export function testEchoRoutes(env: NodeJS.ProcessEnv) {
  const r = express.Router();

  // 🚦 Rate limit *before* heavy JWT verification
  r.use(createTestEchoLimiter(env));

  r.use(requireJwt(env));
  r.use(requireScope(env));

  r.get("/echo", (req, res) => {
    res.json({
      ok: true,
      user: (req as any).user?.sub || null,
      scope: (req as any).user?.scope || "",
      method: "GET",
      route: "GET:/__test__/echo",
    });
  });

  r.post("/echo", (req, res) => {
    res.json({
      ok: true,
      user: (req as any).user?.sub || null,
      scope: (req as any).user?.scope || "",
      method: "POST",
      route: "POST:/__test__/echo",
      body: req.body,
    });
  });

  return r;
}
