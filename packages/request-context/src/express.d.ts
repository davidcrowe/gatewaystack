// packages/request-context/src/express.d.ts

import type { GatewayContext } from "./types";

declare module "express-serve-static-core" {
  interface Request {
    /**
     * Shared Gatewaystack context for this HTTP request.
     * Populated initially by the first gateway middleware (often identifiabl).
     * Enriched by transformabl, validatabl, limitabl, proxyabl, explicabl.
     */
    gateway?: GatewayContext;

    /**
     * Optional alias for backward compatibility.
     * Over time you can migrate away from req.user toward req.gateway.identity.
     */
    user?: GatewayContext["identity"];
  }
}
