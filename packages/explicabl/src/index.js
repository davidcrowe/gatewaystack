import { Router } from "express";
import { healthRoutes } from "./health";
import { auth0LogsWebhook } from "./webhooks/auth0LogWebhook";
export { healthRoutes } from "./health";
export { auth0LogsWebhook } from "./webhooks/auth0LogWebhook";
/**
 * Combined router for the Explicabl layer:
 * - health endpoints
 * - logging/audit webhooks
 */
export function explicablRouter(env) {
    const r = Router();
    // Health routes (public)
    r.use(healthRoutes(env));
    // Webhooks (auth0 logs, etc.)
    r.use("/webhooks/auth0", auth0LogsWebhook);
    // Important: cast router to RequestHandler
    return r;
}
