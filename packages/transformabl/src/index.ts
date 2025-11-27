import type { RequestHandler } from "express";

export interface TransformablConfig {
  /**
   * Placeholder for future config:
   * - PII redaction rules
   * - classification flags
   * - content filters
   */
  redactionRules?: Array<unknown>;
}

/**
 * No-op Transformabl layer for now.
 *
 * Later this is where you'll:
 *  - redact PII from req.body / req.headers
 *  - annotate requests with classification
 *  - normalize input into a canonical shape
 */
export function transformabl(
  _config?: TransformablConfig
): RequestHandler {
  const middleware: RequestHandler = (req, _res, next) => {
    // TODO: implement PII redaction / classification here
    // For now, just pass through untouched.
    return next();
  };

  return middleware;
}
