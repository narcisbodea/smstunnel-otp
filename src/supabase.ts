/**
 * Supabase Auth "Send SMS" hook (HTTPS). Supabase calls your endpoint with the user and the code instead of using its
 * built-in SMS provider; the endpoint hands the code to SMSTunnel and your own phone sends it.
 *
 * Docs: https://supabase.com/docs/guides/auth/auth-hooks/send-sms-hook
 * - Request: Standard Webhooks signature headers, JSON `{ user: { phone, ... }, sms: { otp } }`.
 * - Success: HTTP 200 (we answer `{}`).
 * - Error: `{ "error": { "http_code": <number>, "message": "<text>" } }`, always `Content-Type: application/json`;
 *   429 / 503 with a non-empty `retry-after` header are retried by Supabase (5 s budget in total).
 */
import { sendCode, type CodeTextOptions, type SmsTunnelConnection } from './core';
import { SmsTunnelOtpError, WebhookVerificationError } from './errors';
import { bodyText, json, makeHandler, parseJsonObject, type RawWebhookRequest, type WebhookHandler, type WebhookResult } from './http';
import { RecentWebhookIds, parseWebhookSecrets, verifyWebhook } from './webhooks';

/** Supabase gives the whole hook 5 seconds, retries included. */
export const SUPABASE_DEFAULT_TIMEOUT_MS = 4_000;

export interface SupabaseSendSmsHookOptions extends SmsTunnelConnection {
  /**
   * The hook secret from Dashboard → Authentication → Hooks, as shown there: `v1,whsec_<base64>`. Several secrets
   * separated by `|` (Supabase's `SEND_SMS_HOOK_SECRETS` format) or a list are accepted while you rotate.
   */
  hookSecret: string | string[];
  /** Text around the code, default `"Your verification code is {code}"`. */
  template?: CodeTextOptions['template'];
  /** Default 4000 ms, inside Supabase's 5-second budget. */
  timeoutMs?: number;
  /** Allowed clock difference for `webhook-timestamp`, in seconds (default 300). */
  toleranceSeconds?: number;
}

/** The parts of Supabase's payload this hook reads. */
export interface SupabaseSendSmsPayload {
  user: { id?: string; phone?: string; [key: string]: unknown };
  sms: {
    otp: string;
    /**
     * Where the code goes. Supabase Auth sets it (without the `+`) in current versions: the new number when a user
     * changes it, the factor's number for MFA. Older versions only send `user.phone`.
     */
    phone?: string;
    /** For example `mfa`. */
    sms_type?: string;
    [key: string]: unknown;
  };
  /** The recipient this hook uses: `sms.phone`, else `user.phone`, in international format. */
  to: string;
}

/**
 * Creates the Send SMS hook endpoint.
 *
 * ```ts
 * Deno.serve(createSupabaseSendSmsHook({
 *   apiKey: Deno.env.get('SMSTUNNEL_API_KEY')!,
 *   hookSecret: Deno.env.get('SEND_SMS_HOOK_SECRETS')!,
 * }));
 * ```
 *
 * Returns a Fetch handler `(req: Request) => Promise<Response>`; `handler.process({ method, headers, body })` does
 * the same for frameworks without Fetch requests.
 */
export function createSupabaseSendSmsHook(options: SupabaseSendSmsHookOptions): WebhookHandler {
  if (!options || typeof options.apiKey !== 'string' || !options.apiKey.trim()) {
    throw new SmsTunnelOtpError('createSupabaseSendSmsHook: apiKey is required (your SMSTunnel API key)', { code: 'INVALID_ARGUMENT' });
  }
  parseWebhookSecrets(options.hookSecret); // fail at start-up, not on the first sign-in
  const recent = new RecentWebhookIds();

  return makeHandler(async (request: RawWebhookRequest): Promise<WebhookResult> => {
    if (request.method && request.method.toUpperCase() !== 'POST') {
      return supabaseError(405, 'Method not allowed: Supabase sends this hook as POST', { Allow: 'POST' });
    }

    let webhookId: string;
    try {
      ({ id: webhookId } = await verifyWebhook({
        secret: options.hookSecret,
        headers: request.headers,
        body: request.body,
        toleranceSeconds: options.toleranceSeconds,
      }));
    } catch (err) {
      if (err instanceof WebhookVerificationError) return supabaseError(401, `Invalid webhook signature: ${err.message}`);
      throw err;
    }

    const payload = parseSupabaseSendSmsPayload(bodyText(request.body));
    if (!payload) return supabaseError(400, 'The hook payload has no phone number (sms.phone / user.phone) or no sms.otp');

    if (recent.has(webhookId)) return json(200, {}); // a retry of a code that already went out

    try {
      await sendCode({
        ...options,
        timeoutMs: options.timeoutMs ?? SUPABASE_DEFAULT_TIMEOUT_MS,
        to: payload.to,
        code: payload.sms.otp,
        message: undefined,
        template: options.template,
      });
    } catch (err) {
      return supabaseFailure(err);
    }
    recent.add(webhookId);
    return json(200, {});
  });
}

/** Reads the code (`sms.otp`) and the recipient (`sms.phone`, else `user.phone`); `undefined` when either is missing. */
export function parseSupabaseSendSmsPayload(text: string): SupabaseSendSmsPayload | undefined {
  const data = parseJsonObject(text);
  if (!data) return undefined;
  const user = data.user && typeof data.user === 'object' ? data.user : {};
  const sms = data.sms && typeof data.sms === 'object' ? data.sms : {};
  const otp = sms.otp;
  if ((typeof otp !== 'string' && typeof otp !== 'number') || !String(otp).trim()) return undefined;
  const phone = [sms.phone, user.phone].find((p): p is string => typeof p === 'string' && p.trim() !== '');
  if (!phone) return undefined;
  return { ...data, user, sms: { ...sms, otp: String(otp).trim() }, to: supabasePhone(phone) } as SupabaseSendSmsPayload;
}

/** Supabase stores phone numbers without the leading `+` (`14155550123`); SMSTunnel wants international format. */
export function supabasePhone(phone: string): string {
  const value = phone.trim();
  return /^\d{6,15}$/.test(value) ? `+${value}` : value;
}

function supabaseError(httpCode: number, message: string, headers: Record<string, string> = {}): WebhookResult {
  return json(httpCode, { error: { http_code: httpCode, message } }, headers);
}

function supabaseFailure(err: unknown): WebhookResult {
  if (!(err instanceof SmsTunnelOtpError)) {
    return supabaseError(500, `Failed to send SMS: ${err instanceof Error ? err.message : String(err)}`);
  }
  const message = `Failed to send SMS: ${err.message}`;
  // Supabase retries 429 and 503 when `retry-after` is set; anything else fails the sign-in right away.
  if (err.status === 429) return supabaseError(429, message, { 'retry-after': '2' });
  if (err.retryable) return supabaseError(503, message, { 'retry-after': '2' });
  if (err.status === 400) return supabaseError(400, message);
  return supabaseError(500, message);
}
