import { type RequestHandler } from "express";
export { healthRoutes } from "./health";
export { auth0LogsWebhook } from "./webhooks/auth0LogWebhook";
/**
 * Combined router for the Explicabl layer:
 * - health endpoints
 * - logging/audit webhooks
 */
export declare function explicablRouter(env: NodeJS.ProcessEnv): RequestHandler;
