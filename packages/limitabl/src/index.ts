import type { RequestHandler } from "express";
import rateLimit, { ipKeyGenerator } from "express-rate-limit";

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
      req.user?.sub || req.user?.org_id || ipKeyGenerator(req),
    standardHeaders: true,
    legacyHeaders: false,
  });

  return limiter as unknown as RequestHandler;
}
