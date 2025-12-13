import type { RequestHandler } from "express";
import rateLimit from "express-rate-limit";
import type { Request } from "express";

export interface LimitablConfig {
  /**
   * Rate limit window in milliseconds.
   * e.g. 60000 for 1 minute
   */
  windowMs: number;
  /**
   * Max number of requests per window.
   */
  limit: number;
}

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

/**
 * Express middleware that applies a per-identity rate limit:
 *  - Prefer req.user.sub
 *  - Fallback to req.user.org_id
 *  - Fallback to IP address
 */
export function limitabl(config: LimitablConfig): RequestHandler {
  const limiter = rateLimit({
    windowMs: config.windowMs,
    limit: config.limit,
    keyGenerator: (req: any) =>
      req.user?.sub || req.user?.org_id || keyFromReq(req),
    standardHeaders: true,
    legacyHeaders: false,
  });

  return limiter as unknown as RequestHandler;
}
