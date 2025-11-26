import { createRemoteJWKSet, jwtVerify } from "jose";
/**
 * Escape a string for safe use inside a RegExp literal.
 */
function escapeForRegex(input) {
    return input.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
/**
 * Build a pattern that matches the issuer with or without a trailing slash.
 */
function buildIssuerPattern(issuer) {
    const issuerNoSlash = issuer.replace(/\/+$/, "");
    return new RegExp(`^${escapeForRegex(issuerNoSlash)}\\/?$`);
}
/**
 * Express middleware that:
 *  - Extracts a Bearer token
 *  - Verifies it with JWKS (jose)
 *  - Checks audience and issuer
 *  - Attaches the JWT payload to req.user
 */
export function identifiabl(config) {
    const issuerNoSlash = config.issuer.replace(/\/+$/, "");
    const issuerPattern = buildIssuerPattern(config.issuer);
    const audience = config.audience;
    const jwksUri = config.jwksUri || `${issuerNoSlash}/.well-known/jwks.json`;
    const JWKS = createRemoteJWKSet(new URL(jwksUri));
    const middleware = async (req, res, next) => {
        try {
            const auth = req.headers.authorization || "";
            const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
            if (!token) {
                return res.status(401).json({ error: "missing_bearer" });
            }
            // Verify signature & audience
            const { payload } = await jwtVerify(token, JWKS, { audience });
            // Enforce expected issuer (with or without trailing slash)
            const iss = String(payload.iss || "");
            if (!issuerPattern.test(iss)) {
                return res.status(401).json({
                    error: "invalid_token",
                    detail: `unexpected "iss" claim value: ${iss}`,
                });
            }
            // Attach identity to the request
            req.user = payload;
            return next();
        }
        catch (e) {
            return res
                .status(401)
                .json({ error: "invalid_token", detail: e?.message });
        }
    };
    return middleware;
}
