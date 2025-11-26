import type { RequestHandler } from "express";
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
export declare function withLimitabl(config: LimitablConfig): RequestHandler;
