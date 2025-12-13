import type { Request, Response, NextFunction } from "express";
import type { ProxyablConfig } from "@gatewaystack/proxyabl-core";
import { verifyBearerFromRequest, ensureToolScopesForRequest } from "./auth.js";

export function createProxyablMiddleware(config: ProxyablConfig) {
  return async function proxyablMiddleware(req: Request, res: Response, next: NextFunction) {
    try {
      const identity = await verifyBearerFromRequest(config, req);

      const tool = req.path.split("/").pop();
      if (tool) {
        ensureToolScopesForRequest(config, tool, identity.scopes);
      }

      // attach identity for downstream use (same pattern as Identifiabl)
      (req as any).proxyablIdentity = identity;

      next();
    } catch (e: any) {
      const status = Number(e.status) || 401;
      res.status(status).json({ error: e.message || "Unauthorized" });
    }
  };
}
