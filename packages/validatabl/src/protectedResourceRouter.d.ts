export declare function protectedResourceRouter(cfg: {
    issuer: string;
    audience?: string;
    scopes: string[];
}): import("express-serve-static-core").Router;
