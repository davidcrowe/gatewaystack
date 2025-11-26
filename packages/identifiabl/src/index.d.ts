import type { RequestHandler } from "express";
export interface IdentifiablConfig {
    /**
     * Expected issuer, e.g. "https://example.auth0.com"
     * Can have or not have a trailing slash; we normalize it.
     */
    issuer: string;
    /**
     * Expected audience (API identifier).
     */
    audience: string;
    /**
     * Optional JWKS URI. If not provided, defaults to
     * `${issuerWithoutTrailingSlash}/.well-known/jwks.json`.
     */
    jwksUri?: string;
}
/**
 * Express middleware that:
 *  - Extracts a Bearer token
 *  - Verifies it with JWKS (jose)
 *  - Checks audience and issuer
 *  - Attaches the JWT payload to req.user
 */
export declare function identifiabl(config: IdentifiablConfig): RequestHandler;
