import type { Request, Response } from "express";
export declare function wellKnownOauthProtectedResource(req: Request, res: Response): Promise<void>;
export declare function toolGatewayImpl(req: Request, res: Response): Promise<void>;
export declare function auth0LogWebhook(req: Request, res: Response): Promise<void>;
export declare const toolGatewayRouter: import("express-serve-static-core").Router;
