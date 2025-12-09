### Production Checklist

* ✅ RS256 enforced; JWKS timeout & caching tuned
* ✅ Strict CORS (exact origins)
* ✅ Deny-by-default policies per route/tool
* ✅ Rate-limit per user/tenant with sane ceilings
* ✅ Logs redact PII; audit fields: `{sub, tool, path, decision, latency}`
* ✅ Health probes hooked into your orchestrator
* ✅ *(Optional)* DCR webhook secret rotated; Mgmt API scopes minimal