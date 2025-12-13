// packages/explicabl/src/explicabl.ts

import {
  Router,
  type Request,
  type Response,
  type NextFunction,
  type RequestHandler,
} from "express";
import { healthRoutes } from "./health.js";
import { auth0LogsWebhook } from "./webhooks/auth0LogWebhook.js";

export { healthRoutes } from "./health.js";
export { auth0LogsWebhook } from "./webhooks/auth0LogWebhook.js";

/**
 * MVP Explicabl config
 */
export interface ExplicablConfig {
  serviceName?: string;
  environment?: string;
}

/**
 * MVP Explicabl event shape.
 *
 * Keep this deliberately small for now — we can extend later with
 * tokens, policy IDs, etc. without breaking callers.
 */
export interface ExplicablEvent {
  ts: string;
  kind: "gateway.request";

  serviceName?: string;
  environment?: string;

  // Try to carry some kind of request ID if you have one
  requestId?: string;

  http: {
    method: string;
    path: string;
    status: number;
    latencyMs?: number;
  };

  /**
   * Optional “request context” snapshot.
   *
   * For now we treat this as an opaque blob and just log it. You can
   * wire in your real GatewayContext here (identity, authz, limits, etc.)
   * by putting it on res.locals in your other middleware.
   */
  context?: unknown;
}

/**
 * Simple logger interface – MVP is just a function taking an event.
 */
export type ExplicablLogger = (event: ExplicablEvent) => void;

/**
 * MVP sink: logs one JSON line to console per request.
 */
export function createConsoleLogger(
  config: ExplicablConfig = {},
): ExplicablLogger {
  const defaultServiceName = config.serviceName ?? "gateway-server";
  const defaultEnv = config.environment ?? process.env.NODE_ENV ?? "dev";

  return (event: ExplicablEvent) => {
    const enriched: ExplicablEvent = {
      ...event,
      serviceName: event.serviceName ?? defaultServiceName,
      environment: event.environment ?? defaultEnv,
    };

    // Single-line JSON for easy ingestion
    // eslint-disable-next-line no-console
    console.log("[explicabl]", JSON.stringify(enriched));
  };
}

/**
 * Express middleware that emits one ExplicablEvent when a response finishes.
 *
 * It is intentionally defensive: if no context is present, it still logs
 * method/path/status/latency.
 */
export function explicablLoggingMiddleware(
  logger: ExplicablLogger,
): RequestHandler {
  return (req: Request, res: Response, next: NextFunction) => {
    const startedAt = Date.now();

    res.on("finish", () => {
      const latencyMs = Date.now() - startedAt;

      // Try a few common places where you might stash requestId/context.
      const locals: any = res.locals ?? {};
      const requestId: string | undefined =
        (locals.requestId as string | undefined) ??
        (locals.reqId as string | undefined) ??
        (req.headers["x-request-id"] as string | undefined);

      const context: unknown =
        locals.gatewayContext ??
        locals.context ??
        undefined;

      const event: ExplicablEvent = {
        ts: new Date().toISOString(),
        kind: "gateway.request",
        requestId,
        http: {
          method: req.method,
          path: req.path,
          status: res.statusCode,
          latencyMs,
        },
        context,
      };

      try {
        logger(event);
      } catch (err) {
        // Never break user traffic because logging failed
        // eslint-disable-next-line no-console
        console.error("[explicabl:logger_error]", err);
      }
    });

    next();
  };
}

/**
 * Combined router for the Explicabl layer:
 * - health endpoints
 * - logging/audit webhooks
 *
 * This preserves your existing behavior.
 */
export function explicablRouter(env: NodeJS.ProcessEnv): RequestHandler {
  const r = Router();

  // Health routes (public)
  r.use(healthRoutes(env) as unknown as RequestHandler);

  // Webhooks (auth0 logs, etc.)
  // NOTE: auth0LogsWebhook is already a RequestHandler in your current code,
  // so we do NOT call it as a function here.
  r.use("/webhooks/auth0", auth0LogsWebhook as unknown as RequestHandler);

  // Important: cast router to RequestHandler
  return r as unknown as RequestHandler;
}
