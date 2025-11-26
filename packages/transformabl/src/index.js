/**
 * No-op Transformabl layer for now.
 *
 * Later this is where you'll:
 *  - redact PII from req.body / req.headers
 *  - annotate requests with classification
 *  - normalize input into a canonical shape
 */
export function withTransformabl(_config) {
    const middleware = (req, _res, next) => {
        // TODO: implement PII redaction / classification here
        // For now, just pass through untouched.
        return next();
    };
    return middleware;
}
