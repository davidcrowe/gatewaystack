// packages/identifiabl/src/index.ts
import type { RequestHandler } from "express";
import {
  updateGatewayContext,
  type GatewayIdentity,
} from "@gatewaystack/request-context";
import { createIdentifiablVerifier as coreCreateIdentifiablVerifier } from "identifiabl";

export interface IdentifiablConfig {
  issuer: string;
  audience: string;
  jwksUri?: string;
}

export function identifiabl(config: IdentifiablConfig): RequestHandler {
  const verify = coreCreateIdentifiablVerifier({
    ...config,
    scopeClaim: "scope",
  });

  const middleware: RequestHandler = async (req: any, res, next) => {
    const auth = req.headers.authorization || "";
    const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";

    if (!token) {
      return res.status(401).json({ error: "missing_bearer" });
    }

    const result = await verify(token);
    if (!result.ok) {
      return res.status(401).json(result);
    }

    const identity = result.identity as GatewayIdentity;
    updateGatewayContext({ identity });
    req.user = identity;

    return next();
  };

  return middleware;
}

// 👇 re-export the verifier under the name you want
export const createIdentifiablVerifier = coreCreateIdentifiablVerifier;
