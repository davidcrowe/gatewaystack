export interface ScopeClaims {
    scope?: string | string[];
    scopes?: string[];
}
/**
 * Normalize scopes from various JWT claim shapes into a single space-delimited string.
 */
export declare function getScopeStringFromClaims(claims: ScopeClaims): string;
/**
 * Check whether a given scope is present in the user's scopes.
 */
export declare function hasScope(claims: ScopeClaims, scope: string): boolean;
