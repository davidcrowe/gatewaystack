export * from "./scopes";

export type ProtectedResourceConfig = { issuer: string; audience?: string; scopes: string[] };

export function buildProtectedResourcePayload(cfg: ProtectedResourceConfig) {
  const payload: any = {
    authorization_servers: [cfg.issuer],
    scopes_supported: cfg.scopes
  };
  if (cfg.audience) payload.resource = cfg.audience;
  return payload;
}
