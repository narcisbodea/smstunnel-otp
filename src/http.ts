/** Small helpers shared by the webhook adapters (Supabase, Clerk). */
import type { HeadersInput } from './webhooks';

/** A framework-neutral answer: turn it into a Fetch `Response` with {@link toResponse}, or write it to Express. */
export interface WebhookResult {
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** The raw request, for frameworks without Fetch `Request` objects (Express, Fastify...). */
export interface RawWebhookRequest {
  /** HTTP method; checked when given. */
  method?: string;
  headers: HeadersInput;
  /** The body exactly as received. In Express use `express.raw({ type: 'application/json' })`. */
  body: string | Uint8Array | ArrayBuffer;
}

/** A Fetch handler (Deno.serve, Next.js route, Workers, Bun) that also exposes `process` for other frameworks. */
export type WebhookHandler = ((request: Request) => Promise<Response>) & {
  process(request: RawWebhookRequest): Promise<WebhookResult>;
};

export function json(status: number, value: unknown, extraHeaders: Record<string, string> = {}): WebhookResult {
  return {
    status,
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
    body: JSON.stringify(value),
  };
}

export function toResponse(result: WebhookResult): Response {
  return new Response(result.body, { status: result.status, headers: result.headers });
}

export function makeHandler(process: (request: RawWebhookRequest) => Promise<WebhookResult>): WebhookHandler {
  const handler = async (request: Request): Promise<Response> => {
    const body = request.method === 'POST' ? new Uint8Array(await request.arrayBuffer()) : new Uint8Array(0);
    return toResponse(await process({ method: request.method, headers: request.headers, body }));
  };
  return Object.assign(handler, { process });
}

export function bodyText(body: string | Uint8Array | ArrayBuffer): string {
  if (typeof body === 'string') return body;
  return new TextDecoder().decode(body instanceof ArrayBuffer ? new Uint8Array(body) : body);
}

export function parseJsonObject(text: string): Record<string, any> | undefined {
  try {
    const value = JSON.parse(text);
    return value && typeof value === 'object' && !Array.isArray(value) ? value : undefined;
  } catch {
    return undefined;
  }
}
