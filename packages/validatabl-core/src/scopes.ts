// packages/validatabl-core/src/scopes.ts

export interface ScopeClaims {
  scope?: string | string[];
  scopes?: string[]; // some IdPs put scopes here instead
}

/**
 * Normalize scopes from various JWT claim shapes into a single space-delimited string.
 */
export function getScopeStringFromClaims(claims: ScopeClaims): string {
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
export function hasScope(claims: ScopeClaims, scope: string): boolean {
  const s = getScopeStringFromClaims(claims);
  if (!s) return false;
  const pattern = new RegExp(`(^|\\s)${scope}(\\s|$)`);
  return pattern.test(s);
}
