// packages/proxyabl/src/result.ts

export interface NormalizedProxyResult {
  payload: any;
  isJson: boolean;
  ok: boolean;
  status: number;
}

/**
 * Heuristic check: does this look like a fetch/Response object?
 */
export function isResponseLike(r: any): boolean {
  if (!r || typeof r !== "object") return false;
  return (
    !!(r as any).headers ||
    typeof (r as any).text === "function" ||
    typeof (r as any).json === "function"
  );
}

/**
 * Get content-type from response-like object, supporting both Fetch Headers and
 * plain object headers.
 */
export function getContentTypeFromProxyResponse(r: any): string {
  if (!r || !(r as any).headers) return "";

  const h = (r as any).headers as any;

  // Fetch-style Headers
  if (typeof h.get === "function") {
    return h.get("content-type") || h.get("Content-Type") || "";
  }

  // Plain object style
  const lower = (h["content-type"] ?? h["Content-Type"]) as string | undefined;
  return lower || "";
}

/**
 * Try to read a body from a variety of shapes:
 * - Response.text()
 * - { body: string }
 * - { body: Uint8Array | Buffer }
 * - { body: object } (JSON already parsed)
 */
export async function readBodyFromProxyResponse(
  r: any
): Promise<{ text: string; isJsonGuess: boolean }> {
  if (!r) return { text: "", isJsonGuess: false };

  // 1) Real Response-like object
  if (typeof (r as any).text === "function") {
    const txt = await (r as any).text();
    return { text: txt ?? "", isJsonGuess: true };
  }

  // 2) If there's a body field
  const body = (r as any).body;

  if (typeof body === "string") {
    return { text: body, isJsonGuess: true };
  }

  if (
    body instanceof Uint8Array ||
    (typeof Buffer !== "undefined" && Buffer.isBuffer(body))
  ) {
    const txt = Buffer.from(body).toString("utf8");
    return { text: txt, isJsonGuess: true };
  }

  if (body && typeof body === "object") {
    // already parsed JSON
    return { text: JSON.stringify(body), isJsonGuess: true };
  }

  // 3) Last resort
  return { text: String(body ?? ""), isJsonGuess: false };
}

/**
 * Normalize the result of proxyablClient.callTool into a simple shape that
 * works whether `r` is a real Response or plain JSON.
 */
export async function normalizeProxyablResult(
  r: any
): Promise<NormalizedProxyResult> {
  // Defaults
  let payload: any;
  let isJson = false;
  let ok = true;
  let status = 200;

  if (isResponseLike(r)) {
    const ct = getContentTypeFromProxyResponse(r);
    const looksJson = ct.includes("json");

    if (looksJson && typeof (r as any).json === "function") {
      try {
        payload = await (r as any).json();
        isJson = true;
      } catch {
        // fall through to text / body
      }
    }

    if (!isJson) {
      const { text } = await readBodyFromProxyResponse(r);
      if (looksJson) {
        try {
          payload = JSON.parse(text);
          isJson = true;
        } catch {
          payload = text;
        }
      } else {
        payload = text;
      }
    }

    ok = (r as any).ok !== false;
    status = (r as any).status ?? 200;
  } else {
    // Plain JSON (current Cloud Function behavior)
    payload = r;
    isJson = typeof r === "object" && r !== null;
    ok = (r as any).ok !== false;
    status = 200;
  }

  return { payload, isJson, ok, status };
}
