import type { RequestHandler } from "express";
import { hasScope } from "@gatewaystack/validatabl-core";

export function requireScope(scope: string): RequestHandler {
  return (req: any, res, next) => {
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
