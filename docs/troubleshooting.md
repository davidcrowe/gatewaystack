### Troubleshooting

> **Using Auth0 + ChatGPT?** For Auth0-specific issues (Post-Login Actions, JWE vs JWS tokens, scopes not showing up, etc.), see `docs/auth0/chatgpt-post-login-action.md` → “Troubleshooting checklist”.

**401 with valid token**

* Check `OAUTH_AUDIENCE` matches the token `aud`
* Check `OAUTH_ISSUER` matches token `iss` and the JWKS URL resolves
* Ensure **RS256** is used; HS256 will be rejected when `OAUTH_ENFORCE_ALG=RS256`

**403 on write**

* Your token likely lacks `tool:write`; confirm “Add Permissions in the Access Token” is enabled on the API

**Proxy not injecting user**

* Verify `PROXY_TARGET` is reachable
* Confirm `PROXY_INJECT_HEADER` / `PROXY_INJECT_QUERY` are set and your route is going through the proxy handler

**Rate limit never triggers**

* Lower `RATE_LIMIT_MAX` and ensure identifier (user/tenant) is parsed from the token’s `sub` / `org_id`
