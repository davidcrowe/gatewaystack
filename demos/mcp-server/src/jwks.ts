import { Router } from "express";
import { generateKeyPair, exportJWK, JWK } from "jose";

const alg = "RS256" as const;

// Lazily generate and cache an ephemeral keypair + JWK (dev only)
let keypairPromise: ReturnType<typeof generateKeyPair> | null = null;
let cachedJwk: JWK | null = null;

async function ensureKeys() {
  if (!keypairPromise) {
    keypairPromise = generateKeyPair(alg);
  }

  const { publicKey, privateKey } = await keypairPromise as any;

  if (!cachedJwk) {
    const jwk = await exportJWK(publicKey); // inferred as JWK
    jwk.alg = alg;
    jwk.use = "sig";
    jwk.kid = "demo-key-1";
    cachedJwk = jwk;
  }

  return { privateKey, jwk: cachedJwk };
}

export async function getSigner() {
  return ensureKeys();
}

export function jwksRouter() {
  const r = Router();
  r.get("/.well-known/jwks.json", async (_req, res) => {
    const { jwk } = await ensureKeys();
    res.json({ keys: [jwk] });
  });
  return r;
}
