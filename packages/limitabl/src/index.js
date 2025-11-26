import rateLimit, { ipKeyGenerator } from "express-rate-limit";
/**
 * Express middleware that applies a per-identity rate limit:
 *  - Prefer req.user.sub
 *  - Fallback to req.user.org_id
 *  - Fallback to IP address
 */
export function withLimitabl(config) {
    const limiter = rateLimit({
        windowMs: config.windowMs,
        limit: config.limit,
        keyGenerator: (req) => req.user?.sub || req.user?.org_id || ipKeyGenerator(req),
        standardHeaders: true,
        legacyHeaders: false,
    });
    return limiter;
}
