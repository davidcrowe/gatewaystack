import { hasScope } from "@gatewaystack/validatabl-core";
export function requireScope(scope) {
    return (req, res, next) => {
        const claims = {
            scope: req.user?.scope,
            scopes: req.user?.scopes,
        };
        if (!hasScope(claims, scope)) {
            return res
                .status(403)
                .json({ error: "insufficient_scope", needed: scope });
        }
        return next();
    };
}
