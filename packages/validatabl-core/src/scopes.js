"use strict";
// packages/validatabl-core/src/scopes.ts
Object.defineProperty(exports, "__esModule", { value: true });
exports.getScopeStringFromClaims = getScopeStringFromClaims;
exports.hasScope = hasScope;
/**
 * Normalize scopes from various JWT claim shapes into a single space-delimited string.
 */
function getScopeStringFromClaims(claims) {
    if (typeof claims.scope === "string") {
        return claims.scope;
    }
    if (Array.isArray(claims.scope)) {
        return claims.scope.join(" ");
    }
    if (Array.isArray(claims.scopes)) {
        return claims.scopes.join(" ");
    }
    return "";
}
/**
 * Check whether a given scope is present in the user's scopes.
 */
function hasScope(claims, scope) {
    var s = getScopeStringFromClaims(claims);
    if (!s)
        return false;
    var pattern = new RegExp("(^|\\s)".concat(scope, "(\\s|$)"));
    return pattern.test(s);
}
