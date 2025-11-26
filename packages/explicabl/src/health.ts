import { Router } from "express";
import fetch from "node-fetch";

export function healthRoutes(env: NodeJS.ProcessEnv) {
  const r = Router();

  r.get("/", (_req, res) => {
    res.json({
      ok: true,
      mode: env.MODE || "firebase",
      version: process.env.COMMIT_SHA || "dev",
      time: new Date().toISOString(),
    });
  });

  r.get("/auth0", async (_req, res) => {
    const issuer = env.AUTH0_ISSUER;
    const audience = env.AUTH0_AUDIENCE;
    const jwksUri = env.AUTH0_JWKS_URI;
    const out: any = { issuer, audience, jwksUri, jwksReachable: false };

    try {
      const resp = await fetch(jwksUri!);
      out.jwksReachable = resp.ok;
      if (!resp.ok) out.jwksError = `HTTP ${resp.status}`;
    } catch (e: any) {
      out.jwksError = e?.message || String(e);
    }

    if (env.MGMT_DOMAIN && env.MGMT_CLIENT_ID && env.MGMT_CLIENT_SECRET) {
      out.managementConfigured = true;
      try {
        const tokenResp = await fetch(`https://${env.MGMT_DOMAIN}/oauth/token`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            client_id: env.MGMT_CLIENT_ID,
            client_secret: env.MGMT_CLIENT_SECRET,
            audience: `https://${env.MGMT_DOMAIN}/api/v2/`,
            grant_type: "client_credentials",
          }),
        });
        out.managementTokenOk = tokenResp.ok;
        if (!tokenResp.ok) out.managementError = `HTTP ${tokenResp.status}`;
      } catch (e: any) {
        out.managementTokenOk = false;
        out.managementError = e?.message || String(e);
      }
    } else {
      out.managementConfigured = false;
    }

    res.json(out);
  });

  return r;
}
