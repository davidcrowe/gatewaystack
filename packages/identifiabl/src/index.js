import type { RequestHandler } from "express";
import {
  createGatewayContext,
  type GatewayRequestMeta,
} from "@gatewaystack/request-context";
import {
  createIdentifiablVerifier,
  type IdentifiablCoreConfig,
} from "@gatewaystack/identifiabl-core";

export interface IdentifiablConfig extends IdentifiablCoreConfig {}

/**
 * Express middleware that:
 *  - Extracts a Bearer token
 *  - Uses identifiabl-core to verify it
 *  - Attaches identity to req.gateway.identity
 *  - Also mirrors identity to req.user for convenience
 */
export function identifiabl(config: IdentifiablConfig): RequestHandler {
  const verify = createIdentifiablVerifier(config);

  const middleware: RequestHandler = async (req: any, res, next) => {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

    if (!token) {
      return res.status(401).json({ error: "missing_bearer" });
    }

    const result = await verify(token);

    if (!result.ok) {
      return res
        .status(401)
        .json({ error: result.error, detail: result.detail });
    }

    const { identity } = result;

    // Ensure GatewayContext exists
    if (!req.gateway) {
      const requestMeta: Partial<GatewayRequestMeta> = {
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.headers["user-agent"] as string | undefined,
      };

      req.gateway = createGatewayContext({
        request: requestMeta,
      });
    }

    // Attach identity
    req.gateway.identity = identity;

    // Backward-compatible alias
    req.user = identity;

    return next();
  };

  return middleware;
}
