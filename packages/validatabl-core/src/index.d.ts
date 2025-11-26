export * from "./scopes";
export type ProtectedResourceConfig = {
    issuer: string;
    audience?: string;
    scopes: string[];
};
export declare function buildProtectedResourcePayload(cfg: ProtectedResourceConfig): any;
