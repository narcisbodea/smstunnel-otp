/**
 * Clerk `sms.created` webhook. When you turn **Delivered by Clerk** off for an SMS template (Dashboard →
 * Customization → SMS), Clerk stops sending that text and emits `sms.created` instead; this endpoint hands it to
 * SMSTunnel and your own phone sends it.
 *
 * Docs: https://clerk.com/docs/guides/customizing-clerk/email-sms-templates#delivered-by-clerk
 * - Webhooks come from Svix: `svix-id`, `svix-timestamp`, `svix-signature`, secret `whsec_<base64>` (Standard Webhooks).
 * - Payload: `{ type: 'sms.created', data: { to_phone_number, message, data: { otp_code, ... }, slug, delivered_by_clerk, ... } }`.
 * - Clerk/Svix retries every non-2xx answer; we answer 400 when the signature doesn't verify, like Clerk's own helper.
 */
import { sendCode, sendText, type CodeTextOptions, type SmsTunnelConnection } from './core';
import { SmsTunnelOtpError, WebhookVerificationError } from './errors';
import { bodyText, json, makeHandler, parseJsonObject, type RawWebhookRequest, type WebhookHandler, type WebhookResult } from './http';
import { RecentWebhookIds, parseWebhookSecrets, verifyWebhook } from './webhooks';

export interface ClerkSmsWebhookOptions extends SmsTunnelConnection {
  /** The endpoint's Signing Secret from Clerk Dashboard → Webhooks (`whsec_...`). A list is accepted while you rotate. */
  signingSecret: string | string[];
  /**
   * Text around the code. By default the text Clerk rendered from your SMS template is sent as it is (the code is
   * added if the template lost it).
   */
  template?: CodeTextOptions['template'];
  /**
   * Texts without a code (templates that carry a link or a notice): `'send'` (default) sends them through
   * `/api/v1/sms/send`, counted as regular texts; `'skip'` ignores them.
   */
  nonCodeMessages?: 'send' | 'skip';
  /** Allowed clock difference for `svix-timestamp`, in seconds (default 300). */
  toleranceSeconds?: number;
}

/** The `data` of a Clerk `sms.created` event (Clerk's `SMSMessageJSON`). */
export interface ClerkSmsMessage {
  object?: 'sms_message';
  id?: string;
  slug?: string | null;
  from_phone_number?: string;
  to_phone_number: string;
  phone_number_id?: string | null;
  user_id?: string | null;
  /** The text Clerk rendered from the template. */
  message: string;
  status?: string;
  /** Template variables; `otp_code` for code templates. */
  data?: { otp_code?: string; [key: string]: unknown } | null;
  delivered_by_clerk: boolean;
  [key: string]: unknown;
}

export type ClerkSmsEventAction =
  | { action: 'send-code'; to: string; code: string; message: string }
  | { action: 'send-text'; to: string; message: string }
  | { action: 'skip'; reason: string };

/**
 * Creates the `sms.created` endpoint. Returns a Fetch handler (Next.js route, Remix, Hono, Workers, Bun);
 * `handler.process({ method, headers, body })` does the same for Express and similar.
 *
 * ```ts
 * // app/api/webhooks/clerk-sms/route.ts
 * export const POST = createClerkSmsWebhook({
 *   apiKey: process.env.SMSTUNNEL_API_KEY!,
 *   signingSecret: process.env.CLERK_SMS_WEBHOOK_SIGNING_SECRET!,
 * });
 * ```
 */
export function createClerkSmsWebhook(options: ClerkSmsWebhookOptions): WebhookHandler {
  if (!options || typeof options.apiKey !== 'string' || !options.apiKey.trim()) {
    throw new SmsTunnelOtpError('createClerkSmsWebhook: apiKey is required (your SMSTunnel API key)', { code: 'INVALID_ARGUMENT' });
  }
  parseWebhookSecrets(options.signingSecret);
  const recent = new RecentWebhookIds();

  return makeHandler(async (request: RawWebhookRequest): Promise<WebhookResult> => {
    if (request.method && request.method.toUpperCase() !== 'POST') {
      return json(405, { error: 'Method not allowed' }, { Allow: 'POST' });
    }

    let webhookId: string;
    try {
      ({ id: webhookId } = await verifyWebhook({
        secret: options.signingSecret,
        headers: request.headers,
        body: request.body,
        toleranceSeconds: options.toleranceSeconds,
      }));
    } catch (err) {
      if (err instanceof WebhookVerificationError) return json(400, { error: `Webhook verification failed: ${err.message}` });
      throw err;
    }

    const event = parseJsonObject(bodyText(request.body));
    if (!event) return json(400, { error: 'The webhook body is not a JSON object' });

    const plan = planClerkSmsEvent(event, options.nonCodeMessages ?? 'send');
    if (plan.action === 'skip') return json(200, { ok: true, skipped: plan.reason });
    if (recent.has(webhookId)) return json(200, { ok: true, skipped: 'already sent' });

    try {
      const result =
        plan.action === 'send-code'
          ? await sendCode({ ...options, to: plan.to, code: plan.code, message: options.template ? undefined : plan.message, template: options.template })
          : await sendText({ ...options, to: plan.to, message: plan.message });
      recent.add(webhookId);
      return json(200, { ok: true, messageId: result.messageId, queued: result.queued });
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const status = err instanceof SmsTunnelOtpError ? (err.retryable ? 503 : err.status === 400 ? 400 : 500) : 500;
      return json(status, { error: message, code: err instanceof SmsTunnelOtpError ? err.code : undefined });
    }
  });
}

/** Decides what to do with a verified Clerk event. Exported for tests and custom handlers. */
export function planClerkSmsEvent(event: Record<string, any>, nonCodeMessages: 'send' | 'skip' = 'send'): ClerkSmsEventAction {
  if (event.type !== 'sms.created') return { action: 'skip', reason: `not an sms.created event (${String(event.type)})` };
  const sms = event.data as ClerkSmsMessage | undefined;
  if (!sms || typeof sms !== 'object') return { action: 'skip', reason: 'sms.created without data' };
  if (sms.delivered_by_clerk === true) {
    return { action: 'skip', reason: 'Clerk delivers this template itself (Delivered by Clerk is on)' };
  }
  const to = typeof sms.to_phone_number === 'string' ? sms.to_phone_number.trim() : '';
  if (!to) return { action: 'skip', reason: 'sms.created without to_phone_number' };
  const message = typeof sms.message === 'string' ? sms.message : '';
  const rawCode = sms.data && typeof sms.data === 'object' ? sms.data.otp_code : undefined;
  const code = typeof rawCode === 'string' || typeof rawCode === 'number' ? String(rawCode).trim() : '';
  if (code) return { action: 'send-code', to, code, message };
  if (nonCodeMessages === 'skip') return { action: 'skip', reason: `no code in this text (${sms.slug ?? 'unknown template'})` };
  if (!message.trim()) return { action: 'skip', reason: 'sms.created with an empty message' };
  return { action: 'send-text', to, message };
}
