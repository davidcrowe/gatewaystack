export interface OidcConfig {
  /**
   * OIDC / OAuth issuer, e.g. "https://YOUR_TENANT.us.auth0.com".
   * Trailing slashes will be trimmed internally.
   */
  issuer: string;
  /**
   * Optional audience (API identifier) to enforce on incoming access tokens.
   */
  audience?: string;
  /**
   * Optional explicit JWKS URI. If omitted, will default to `${issuer}/.well-known/jwks.json`.
   */
  jwksUri?: string;
}

export interface ToolScopesConfig {
  /**
   * Map from tool name → list of required scopes/permissions.
   * Example:
   * {
   *   "listEvents": ["inner.events:read"],
   *   "chatWithEmbeddingsv3": ["inner.dreams:write"]
   * }
   */
  [toolName: string]: string[];
}

export interface ProxyConfig {
  /**
   * Base upstream URL, e.g. "http://127.0.0.1:3333".
   * Must be http/https and will be validated.
   */
  target: string;
  /**
   * Path prefix on the gateway side, e.g. "/proxy". Defaults to "/proxy".
   */
  prefix?: string;
  /**
   * Allowed upstream path prefixes (SSRF mitigation).
   * Example: ["/api", "/health"]. Defaults to ["/"].
   */
  allowedPaths?: string[];
  /**
   * Optional header to inject with the verified subject (user id), e.g. "x-user-id".
   */
  injectHeader?: string;
  /**
   * Optional query param to inject with the verified subject, e.g. "userId".
   */
  injectQuery?: string;
  /**
   * Upstream timeout in milliseconds. Defaults to 5000.
   */
  timeoutMs?: number;
}

export interface Auth0DcrConfig {
  /**
   * Auth0 tenant domain, e.g. "my-tenant.us.auth0.com".
   */
  mgmtDomain: string;
  /**
   * Auth0 Management API client_id used for DCR promotion.
   */
  clientId: string;
  /**
   * Auth0 Management API client_secret used for DCR promotion.
   */
  clientSecret: string;
  /**
   * Shared secret used to authenticate the Auth0 Log Stream webhook.
   */
  logWebhookSecret: string;
  /**
   * Optional Auth0 connection name for Google (default "google-oauth2").
   */
  googleConnectionName?: string;
}

export interface ProxyablConfig {
  /**
   * OIDC / OAuth configuration for validating access tokens.
   */
  oidc: OidcConfig;

  /**
   * Map from tool name → required scopes/permissions.
   */
  toolScopes: ToolScopesConfig;

  /**
   * Base URL for downstream tools/functions, e.g. your Cloud Functions base.
   * Example: "https://us-central1-<PROJECT>.cloudfunctions.net".
   */
  functionsBase?: string;

  /**
   * Allowed origin for CORS. Defaults to "*".
   */
  appOrigin?: string;

  /**
   * Optional reverse proxy configuration for /proxy-style endpoints.
   */
  proxy?: ProxyConfig;

  /**
   * Optional Auth0 DCR automation configuration.
   * If omitted or null, the DCR webhook route can be disabled.
   */
  auth0Dcr?: Auth0DcrConfig | null;
}

/**
 * Parses a TOOL_SCOPES_JSON-style string into a ToolScopesConfig.
 * Example raw: {"listEvents":["inner.events:read"],"chatWithEmbeddingsv3":["inner.dreams:write"]}
 */
export function parseToolScopesJson(raw?: string | null): ToolScopesConfig {
  if (!raw) return {};
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object") return {};
    const out: ToolScopesConfig = {};
    for (const [name, scopes] of Object.entries(parsed)) {
      if (Array.isArray(scopes)) {
        out[name] = scopes.filter((s): s is string => typeof s === "string" && s.trim().length > 0);
      }
    }
    return out;
  } catch {
    // If JSON is invalid, fail closed with empty config.
    return {};
  }
}

export interface EnvLike {
  [key: string]: string | undefined;
}

export function trimTrailingSlashes(input: string): string {
  let out = input;
  while (out.endsWith("/")) {
    out = out.slice(0, -1);
  }
  return out;
}

/**
 * Builds a ProxyablConfig from process.env-style variables.
 * This is a convenience for apps that prefer env-driven configuration.
 *
 * NOTE: This does not validate the values; the router should still perform
 * some sanity checks (issuer format, proxy target scheme, etc.).
 */
export function configFromEnv(env: EnvLike = process.env): ProxyablConfig {
  const rawIssuer = env.OAUTH_ISSUER ?? "https://YOUR_TENANT.us.auth0.com/";
  const issuerTrimmed = trimTrailingSlashes(rawIssuer);

  const oidc: OidcConfig = {
    issuer: issuerTrimmed,
    audience: env.OAUTH_AUDIENCE || undefined,
    jwksUri: env.JWKS_URI || `${issuerTrimmed}/.well-known/jwks.json`
  };

  const toolScopes = parseToolScopesJson(env.TOOL_SCOPES_JSON);

  const rawFunctionsBase =
    env.FUNCTIONS_BASE ??
    "https://us-central1-<YOUR_PROJECT_ID>.cloudfunctions.net";
  const functionsBase = trimTrailingSlashes(rawFunctionsBase);

  const appOrigin = env.APP_ORIGIN || "*";

  // Proxy configuration (optional). Only set if PROXY_TARGET is present.
  let proxy: ProxyConfig | undefined;
  if (env.PROXY_TARGET) {
    const allowedPathsEnv = env.PROXY_ALLOWED_PATHS || "/";
    const allowedPaths = allowedPathsEnv
      .split(",")
      .map(p => p.trim())
      .filter(p => p.length > 0);

    proxy = {
      target: env.PROXY_TARGET,
      prefix: env.PROXY_PREFIX || "/proxy",
      allowedPaths: allowedPaths.length ? allowedPaths : ["/"],
      injectHeader: env.PROXY_INJECT_HEADER || undefined,
      injectQuery: env.PROXY_INJECT_QUERY || undefined,
      timeoutMs: env.PROXY_TIMEOUT_MS ? Number(env.PROXY_TIMEOUT_MS) || undefined : undefined
    };
  }

  // Auth0 DCR config (optional)
  let auth0Dcr: Auth0DcrConfig | null = null;
  const mgmtDomain = env.MGMT_DOMAIN;
  const mgmtClientId = env.MGMT_CLIENT_ID;
  const mgmtClientSecret = env.MGMT_CLIENT_SECRET;
  const logWebhookSecret = env.LOG_WEBHOOK_SECRET;

  if (mgmtDomain && mgmtClientId && mgmtClientSecret && logWebhookSecret) {
    auth0Dcr = {
      mgmtDomain,
      clientId: mgmtClientId,
      clientSecret: mgmtClientSecret,
      logWebhookSecret,
      googleConnectionName: env.GOOGLE_CONNECTION_NAME || "google-oauth2"
    };
  }

  return {
    oidc,
    toolScopes,
    functionsBase,
    appOrigin,
    proxy,
    auth0Dcr
  };
}


